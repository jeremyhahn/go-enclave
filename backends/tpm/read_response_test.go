package tpm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

// readStep is one Read a scriptedReader answers: up to len(b) bytes of
// data, then err once data is spent.
type readStep struct {
	data []byte
	err  error
}

// scriptedReader answers each Read from its steps in turn, and io.EOF
// once they are spent.
type scriptedReader struct{ steps []readStep }

func (s *scriptedReader) Read(b []byte) (int, error) {
	if len(s.steps) == 0 {
		return 0, io.EOF
	}
	st := &s.steps[0]
	n := copy(b, st.data)
	st.data = st.data[n:]
	if len(st.data) > 0 {
		return n, nil
	}
	err := st.err
	s.steps = s.steps[1:]
	return n, err
}

// chunkReader returns resp in reads of at most chunk bytes; with eofWith
// set, the read that empties resp also returns io.EOF.
type chunkReader struct {
	resp    []byte
	chunk   int
	eofWith bool
}

func (c *chunkReader) Read(b []byte) (int, error) {
	if len(c.resp) == 0 {
		return 0, io.EOF
	}
	n := copy(b[:min(len(b), c.chunk)], c.resp)
	c.resp = c.resp[n:]
	if c.eofWith && len(c.resp) == 0 {
		return n, io.EOF
	}
	return n, nil
}

// tpmResponse frames a response of size bytes: tag, size, response code,
// then a counting payload.
func tpmResponse(size int) []byte {
	b := make([]byte, size)
	b[0], b[1] = 0x80, 0x01
	binary.BigEndian.PutUint32(b[2:6], uint32(size))
	for i := 10; i < size; i++ {
		b[i] = byte(i)
	}
	return b
}

var errInjected = errors.New("injected read failure")

// errOutOfRange stands for readResponse's unexported size-field refusal.
var errOutOfRange = errors.New("size out of range")

// readErrClass maps readResponse's error to the class the tests expect.
func readErrClass(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.ErrNoProgress), errors.Is(err, errInjected):
		return err
	default:
		return errOutOfRange
	}
}

func TestReadResponse(t *testing.T) {
	valid := tpmResponse(14)
	cases := []struct {
		name    string
		r       io.Reader
		bufLen  int
		wantN   int
		wantErr error
	}{
		{"one_byte_reader", iotest.OneByteReader(bytes.NewReader(valid)), 32, 14, nil},
		{"half_reader", iotest.HalfReader(bytes.NewReader(valid)), 32, 14, nil},
		{"no_progress_before_header", &scriptedReader{[]readStep{{valid[:4], nil}, {nil, nil}}}, 32, 0, io.ErrNoProgress},
		{"no_progress_after_header", &scriptedReader{[]readStep{{valid[:12], nil}, {nil, nil}}}, 32, 0, io.ErrNoProgress},
		{"error_after_4_bytes", &scriptedReader{[]readStep{{valid[:4], nil}, {nil, errInjected}}}, 32, 0, errInjected},
		{"error_after_12_bytes", &scriptedReader{[]readStep{{valid[:12], errInjected}}}, 32, 0, errInjected},
		{"data_and_eof_complete", &scriptedReader{[]readStep{{valid, io.EOF}}}, 32, 14, nil},
		{"data_and_error_complete", &scriptedReader{[]readStep{{valid, errInjected}}}, 32, 14, nil},
		{"bytes_after_size", bytes.NewReader(append(append([]byte(nil), valid...), 9, 9, 9)), 32, 14, nil},
		{"header_only", bytes.NewReader(tpmResponse(10)), 32, 10, nil},
		{"size_is_buffer", bytes.NewReader(valid), 14, 14, nil},
		{"size_past_buffer", bytes.NewReader(valid), 13, 0, errOutOfRange},
		{"size_below_header", bytes.NewReader([]byte{0x80, 0x01, 0, 0, 0, 9, 0, 0, 0, 0}), 32, 0, errOutOfRange},
		{"eof_after_header", &scriptedReader{[]readStep{{valid[:10], io.EOF}}}, 32, 0, io.ErrUnexpectedEOF},
		{"eof_before_header", bytes.NewReader(valid[:4]), 32, 0, io.ErrUnexpectedEOF},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := make([]byte, c.bufLen)
			n, err := readResponse(c.r, buf)
			if n != c.wantN || readErrClass(err) != c.wantErr {
				t.Fatalf("readResponse = %d, %v; want %d, %v", n, err, c.wantN, c.wantErr)
			}
			if err == nil && n == len(valid) && !bytes.Equal(buf[:n], valid) {
				t.Fatalf("read %x, want %x", buf[:n], valid)
			}
		})
	}
}

// FuzzReadResponse reads data[1:] through a chunkReader whose chunk size
// and EOF placement come from data[0], and checks readResponse against an
// oracle that decodes the size field itself.
func FuzzReadResponse(f *testing.F) {
	for _, resp := range [][]byte{
		tpmResponse(14), tpmResponse(10), tpmResponse(64), tpmResponse(65),
		append(tpmResponse(14), 9, 9, 9), tpmResponse(14)[:12], tpmResponse(14)[:4],
		{0x80, 0x01, 0, 0, 0, 9, 0, 0, 0, 0},
	} {
		for _, ctl := range []byte{0x00, 0x02, 0x0f, 0x80, 0x8f} {
			f.Add(append([]byte{ctl}, resp...))
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		const bufLen, header = 64, 10
		resp := data[1:]
		r := &chunkReader{resp: resp, chunk: int(data[0]&0x0f) + 1, eofWith: data[0]&0x80 != 0}
		buf := make([]byte, bufLen)
		n, err := readResponse(r, buf)

		wantN, wantErr := 0, io.ErrUnexpectedEOF
		if len(resp) >= header {
			size := binary.BigEndian.Uint32(resp[2:6])
			switch {
			case size < header || size > bufLen:
				wantErr = errOutOfRange
			case uint32(len(resp)) >= size:
				wantN, wantErr = int(size), nil
			}
		}
		if n < 0 || n > len(buf) {
			t.Fatalf("readResponse returned %d for a %d-byte buffer", n, len(buf))
		}
		if n != wantN || readErrClass(err) != wantErr {
			t.Fatalf("readResponse = %d, %v; want %d, %v", n, err, wantN, wantErr)
		}
		if err == nil && !bytes.Equal(buf[:n], resp[:n]) {
			t.Fatalf("read %x, want %x", buf[:n], resp[:n])
		}
	})
}
