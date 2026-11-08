//go:build linux

package tpm

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/google/go-tpm/tpm2"
	"golang.org/x/sys/unix"
)

// fakeTPM is enough of a TPM, over an in-memory stream, for go-tpm's
// unsalted HMAC session and the provider's TPM2_Create and TPM2_Unseal. It
// checks each authorized command's HMAC, decrypts TPM2_Create's first
// parameter, and encrypts TPM2_Unseal's response, as a TPM does (Part 1,
// 19.6 and 21.3). The session is unsalted and unbound, so its session key is
// empty and the fake derives every key from the nonces alone. The plaintext
// lives only in locked mappings: secret, and received, which Create's
// decrypted inSensitive lands in.
type fakeTPM struct {
	alloc    allocator
	name     tpm2.TPM2BName // the one handle each authorized command names
	secret   []byte         // what TPM2_Unseal returns
	received []byte         // TPM2_Create's decrypted TPMS_SENSITIVE_CREATE
	nonceTPM []byte
	rsp      []byte
	err      error // the first malformed command
}

const fakeSessionHandle = 0x02000000

func (f *fakeTPM) Write(cmd []byte) (int, error) {
	if f.err == nil {
		f.rsp, f.err = f.answer(cmd)
	}
	if f.err != nil {
		f.rsp = []byte{0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x01} // TPM_RC_FAILURE
	}
	return len(cmd), nil
}

func (f *fakeTPM) Read(b []byte) (int, error) {
	if len(f.rsp) == 0 {
		return 0, io.EOF
	}
	n := copy(b, f.rsp)
	f.rsp = f.rsp[n:]
	return n, nil
}

func (f *fakeTPM) Close() error { return nil }

func (f *fakeTPM) answer(cmd []byte) ([]byte, error) {
	if len(cmd) < 10 || int(binary.BigEndian.Uint32(cmd[2:6])) != len(cmd) {
		return nil, fmt.Errorf("command size field %x does not match %d bytes", cmd[:min(len(cmd), 6)], len(cmd))
	}
	cc := tpm2.TPMCC(binary.BigEndian.Uint32(cmd[6:10]))
	switch cc {
	case tpm2.TPMCCStartAuthSession:
		f.nonceTPM = make([]byte, 16)
		_, _ = rand.Read(f.nonceTPM)
		body := binary.BigEndian.AppendUint32(nil, fakeSessionHandle)
		body = append(binary.BigEndian.AppendUint16(body, 16), f.nonceTPM...)
		return fakeResponse(0x8001, body), nil
	case tpm2.TPMCCFlushContext:
		return fakeResponse(0x8001, nil), nil
	case tpm2.TPMCCCreate, tpm2.TPMCCUnseal:
		return f.authorized(cc, cmd)
	}
	return nil, fmt.Errorf("unexpected command %v", cc)
}

// authorized checks a command with one handle and one session, and answers
// it with the response the session's HMAC and encryption cover.
func (f *fakeTPM) authorized(cc tpm2.TPMCC, cmd []byte) ([]byte, error) {
	if binary.BigEndian.Uint16(cmd) != 0x8002 || len(cmd) < 18 {
		return nil, fmt.Errorf("%v: not a one-handle command with sessions", cc)
	}
	authSize := int(binary.BigEndian.Uint32(cmd[14:18]))
	if 18+authSize > len(cmd) {
		return nil, fmt.Errorf("%v: authorization size %d runs past the command", cc, authSize)
	}
	auth, err := tpm2.Unmarshal[tpm2.TPMSAuthCommand](cmd[18 : 18+authSize])
	if err != nil || auth.Handle != fakeSessionHandle {
		return nil, fmt.Errorf("%v: authorization area: %v", cc, err)
	}
	params := cmd[18+authSize:]
	attrs := tpm2.Marshal(auth.Attributes)
	cp := sha256.New()
	cp.Write(binary.BigEndian.AppendUint32(nil, uint32(cc)))
	cp.Write(f.name.Buffer)
	cp.Write(params)
	if !hmac.Equal(fakeHMAC(cp.Sum(nil), auth.Nonce.Buffer, f.nonceTPM, attrs), auth.Authorization.Buffer) {
		return nil, fmt.Errorf("%v: the authorization HMAC does not verify", cc)
	}
	nonceCaller := auth.Nonce.Buffer

	var out []byte
	switch cc {
	case tpm2.TPMCCCreate:
		if len(params) < 2 || 2+int(binary.BigEndian.Uint16(params)) > len(params) {
			return nil, fmt.Errorf("TPM2_Create: inSensitive runs past the command")
		}
		first := params[2 : 2+int(binary.BigEndian.Uint16(params))]
		if f.received, err = f.alloc.alloc(len(first)); err != nil {
			return nil, err
		}
		fakeCFB(nonceCaller, f.nonceTPM, false).XORKeyStream(f.received, first)
		if !auth.Attributes.Decrypt {
			return nil, fmt.Errorf("TPM2_Create: the session does not decrypt inSensitive")
		}
		public := tpm2.Marshal(tpm2.New2B(sealedTemplate(make([]byte, 32))))
		out = append(binary.BigEndian.AppendUint16(nil, 16), bytes.Repeat([]byte{0x5a}, 16)...) // outPrivate
		out = append(out, public...)                                                            // outPublic
		out = append(out, 0, 0, 0, 0)                                                           // creationData, creationHash
		out = append(out, 0x80, 0x21, 0x40, 0, 0, 1, 0, 0)                                      // creationTicket
	case tpm2.TPMCCUnseal:
		if !auth.Attributes.Encrypt {
			return nil, fmt.Errorf("TPM2_Unseal: the session does not encrypt outData")
		}
		f.nonceTPM = make([]byte, 16)
		_, _ = rand.Read(f.nonceTPM)
		out = binary.BigEndian.AppendUint16(nil, uint16(len(f.secret)))
		out = append(out, make([]byte, len(f.secret))...)
		fakeCFB(f.nonceTPM, nonceCaller, true).XORKeyStream(out[2:], f.secret)
	}
	if cc == tpm2.TPMCCCreate {
		f.nonceTPM = make([]byte, 16)
		_, _ = rand.Read(f.nonceTPM)
	}
	rp := sha256.New()
	rp.Write(make([]byte, 4)) // TPM_RC_SUCCESS
	rp.Write(binary.BigEndian.AppendUint32(nil, uint32(cc)))
	rp.Write(out)
	body := binary.BigEndian.AppendUint32(nil, uint32(len(out)))
	body = append(body, out...)
	body = append(binary.BigEndian.AppendUint16(body, 16), f.nonceTPM...)
	body = append(body, attrs...)
	mac := fakeHMAC(rp.Sum(nil), f.nonceTPM, nonceCaller, attrs)
	body = append(binary.BigEndian.AppendUint16(body, uint16(len(mac))), mac...)
	return fakeResponse(0x8002, body), nil
}

// fakeHMAC is the session HMAC under an empty key: an unsalted, unbound
// session over an empty authValue.
func fakeHMAC(digest, newer, older, attrs []byte) []byte {
	m := hmac.New(sha256.New, nil)
	m.Write(digest)
	m.Write(newer)
	m.Write(older)
	m.Write(attrs)
	return m.Sum(nil)
}

// fakeCFB is the session's AES-128-CFB parameter cipher, keyed from the
// nonces in the order the direction takes (Part 1, 21.3).
func fakeCFB(newer, older []byte, encrypt bool) cipher.Stream {
	keyIV := tpm2.KDFa(crypto.SHA256, nil, "CFB", newer, older, 256)
	block, err := aes.NewCipher(keyIV[:16])
	if err != nil {
		panic(err)
	}
	if encrypt {
		return cipher.NewCFBEncrypter(block, keyIV[16:])
	}
	return cipher.NewCFBDecrypter(block, keyIV[16:])
}

func fakeResponse(tag uint16, body []byte) []byte {
	rsp := binary.BigEndian.AppendUint16(nil, tag)
	rsp = binary.BigEndian.AppendUint32(rsp, uint32(10+len(body)))
	rsp = append(rsp, 0, 0, 0, 0)
	return append(rsp, body...)
}

// newFakeTPMDevice returns a device over a fakeTPM whose secret is a random
// 32-byte key in locked memory, and a session started on it that encrypts
// the command's first parameter if encryptIn, else the response's.
func newFakeTPMDevice(t *testing.T, encryptIn bool) (*fakeTPM, *tpmDevice, session) {
	t.Helper()
	alloc := newAllocator()
	secret, err := alloc.alloc(32)
	if err != nil {
		t.Skipf("locked memory is unavailable: %v", err)
	}
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	f := &fakeTPM{alloc: alloc, secret: secret, name: tpm2.TPM2BName{Buffer: append([]byte{0, 0x0b}, bytes.Repeat([]byte{7}, 32)...)}}
	tr, err := newStreamTransport(f, "fake", alloc)
	if err != nil {
		t.Fatal(err)
	}
	d := &tpmDevice{t: tr}
	dir := tpm2.EncryptOut
	if encryptIn {
		dir = tpm2.EncryptIn
	}
	s, _, err := tpm2.HMACSession(tr, tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, dir))
	if err != nil {
		t.Fatalf("starting the session on the fake: %v", err)
	}
	t.Cleanup(func() {
		alloc.free(f.secret)
		_ = d.close()
	})
	return f, d, session{handle: s.Handle(), auth: s}
}

// residentCopies returns the readable anonymous or writable mappings of this
// process holding needle anywhere but at needle itself. Mappings of 1 GiB or
// more are the race detector's shadow, never a heap.
func residentCopies(t *testing.T, needle []byte) []string {
	t.Helper()
	maps, err := os.Open("/proc/self/maps")
	if err != nil {
		t.Skipf("no /proc/self/maps: %v", err)
	}
	defer func() { _ = maps.Close() }()
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		t.Skipf("no /proc/self/mem: %v", err)
	}
	defer func() { _ = mem.Close() }()
	buf, err := unix.Mmap(-1, 0, 1<<20, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { clear(buf); _ = unix.Munmap(buf) }()
	skip := map[uintptr]bool{uintptr(unsafe.Pointer(&needle[0])): true}
	bufLo := uintptr(unsafe.Pointer(&buf[0]))

	var hits []string
	sc := bufio.NewScanner(maps)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 || !strings.HasPrefix(f[1], "r") {
			continue
		}
		path := strings.Join(f[5:], " ")
		if path == "[vvar]" || path == "[vvar_vclock]" || path == "[vsyscall]" {
			continue
		}
		if path != "" && !strings.HasPrefix(path, "[") && f[1][1] != 'w' {
			continue
		}
		lo, hi, ok := strings.Cut(f[0], "-")
		l, err1 := strconv.ParseUint(lo, 16, 64)
		h, err2 := strconv.ParseUint(hi, 16, 64)
		if !ok || err1 != nil || err2 != nil || h-l >= 1<<30 || uintptr(l) == bufLo {
			continue
		}
		for off := l; off < h; {
			n := min(uint64(len(buf)), h-off)
			read, _ := mem.ReadAt(buf[:n], int64(off))
			for i := 0; read > 0; {
				j := bytes.Index(buf[i:read], needle)
				if j < 0 {
					break
				}
				if at := uintptr(off) + uintptr(i+j); !skip[at] {
					hits = append(hits, sc.Text())
				}
				i += j + 1
			}
			if read <= len(needle) {
				break
			}
			off += uint64(read - len(needle) + 1)
		}
	}
	return hits
}

func TestTPMDevice_UnsealLeavesNoCopy(t *testing.T) {
	f, d, s := newFakeTPMDevice(t, false)
	dst, err := f.alloc.alloc(maxKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	n, err := d.unseal(object{handle: 0x80000001, name: f.name}, s, dst)
	if err != nil || f.err != nil {
		t.Fatalf("unseal: %v; the fake saw: %v", err, f.err)
	}
	if n != len(f.secret) || !bytes.Equal(dst[:n], f.secret) {
		t.Fatalf("unseal returned %d bytes that are not the sealed key", n)
	}
	clear(dst)
	f.alloc.free(dst)
	if hits := residentCopies(t, f.secret); len(hits) > 0 {
		t.Fatalf("after unseal returned and its destination was wiped, the key is resident in %d mapping(s): %q", len(hits), hits)
	}
}

func TestTPMDevice_CreateLeavesNoCopy(t *testing.T) {
	f, d, s := newFakeTPMDevice(t, true)
	data, err := f.alloc.alloc(len(f.secret))
	if err != nil {
		t.Fatal(err)
	}
	copy(data, f.secret)
	public, private, err := d.create(object{handle: 0x80000000, name: f.name}, s, data)
	if err != nil || f.err != nil {
		t.Fatalf("create: %v; the fake saw: %v", err, f.err)
	}
	if len(public) != sealedPublicBytes || len(private) != 16 {
		t.Fatalf("create returned a %d-byte public and a %d-byte private area", len(public), len(private))
	}
	// TPMS_SENSITIVE_CREATE: an empty userAuth, then data.
	want := append([]byte{0, 0, 0, byte(len(f.secret))}, f.secret...)
	got := bytes.Equal(f.received, want)
	clear(want)
	clear(data)
	f.alloc.free(data)
	clear(f.received)
	f.alloc.free(f.received)
	if !got {
		t.Fatal("the TPM did not receive the key as inSensitive.data")
	}
	if hits := residentCopies(t, f.secret); len(hits) > 0 {
		t.Fatalf("after create returned and its transient was wiped, the key is resident in %d mapping(s): %q", len(hits), hits)
	}
}
