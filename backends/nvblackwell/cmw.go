package nvblackwell

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// The CMW JSON form (RATS Conceptual Message Wrappers): a record is the array
// [type, value, ind?], type a media type, value base64url without padding,
// ind the optional cm-ind bit set; a collection is an object from text labels
// to records or nested collections, with "__cmwc_t" reserved for the
// collection's own type.

// cmwIndEvidence is the cm-ind bit for evidence.
const cmwIndEvidence uint = 1 << 2

// cmwCollectionTypeLabel is the label CMW reserves for a collection's type.
const cmwCollectionTypeLabel = "__cmwc_t"

// mediaTypePEMChain is a PEM certificate chain, the type of both chains
// NVML returns.
const mediaTypePEMChain = "application/pem-certificate-chain"

// errMalformedCMW reports a member the encoder cannot write as CMW.
var errMalformedCMW = errors.New("nvidia-blackwell: malformed CMW member")

// cmw is one CMW: a record or a collection.
type cmw interface {
	cmwJSON(label string) (any, error)
}

// cmwRecord is a CMW record.
type cmwRecord struct {
	// Type is the media type of Value.
	Type string
	// Value is the wrapped message.
	Value []byte
	// Ind is the cm-ind bit set; 0 leaves it out.
	Ind uint
}

func (r cmwRecord) cmwJSON(label string) (any, error) {
	if r.Type == "" {
		return nil, fmt.Errorf("%w: %s: no media type", errMalformedCMW, strconv.Quote(label))
	}
	if len(r.Value) == 0 {
		return nil, fmt.Errorf("%w: %s: empty value", errMalformedCMW, strconv.Quote(label))
	}
	v := base64.RawURLEncoding.EncodeToString(r.Value)
	if r.Ind == 0 {
		return []any{r.Type, v}, nil
	}
	return []any{r.Type, v, r.Ind}, nil
}

// cmwCollection is a CMW collection, label to member.
type cmwCollection map[string]cmw

func (c cmwCollection) cmwJSON(label string) (any, error) {
	if len(c) == 0 {
		return nil, fmt.Errorf("%w: %s: empty collection", errMalformedCMW, strconv.Quote(label))
	}
	out := make(map[string]any, len(c))
	for l, m := range c {
		if l == "" || l == cmwCollectionTypeLabel {
			return nil, fmt.Errorf("%w: label %s", errMalformedCMW, strconv.Quote(l))
		}
		if m == nil {
			return nil, fmt.Errorf("%w: %s: no member", errMalformedCMW, strconv.Quote(l))
		}
		v, err := m.cmwJSON(l)
		if err != nil {
			return nil, err
		}
		out[l] = v
	}
	return out, nil
}

// encodeCMW writes c in the CMW JSON form. encoding/json sorts the labels,
// so equal collections encode to equal bytes.
func encodeCMW(c cmwCollection) ([]byte, error) {
	v, err := c.cmwJSON("")
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}
