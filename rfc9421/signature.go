package rfc9421

import (
	"net/http"
	"strings"

	"codeberg.org/reiver/go-erorr"
	"codeberg.org/reiver/go-field"
	"github.com/reiver/go-rfc9651"

	"github.com/reiver/go-httpsig"
)

// Signature is one signature on a message: its label, its parameters, and the signature bytes.
type Signature struct {
	Label  string
	Params SignatureParams
	Value  []byte
}

// Requirements are what an application requires of the signature it verifies (RFC 9421 §3.2.1).
type Requirements struct {
	// Tag identifies the signature: there must be exactly one signature with this "tag" parameter.
	// (Labels carry no meaning, so the signature is found by its tag, under whatever label.)
	Tag string

	// Components are exactly the components the signature must cover, in order.
	Components []Component

	// Algorithm is the algorithm the signature must use. If the signature has an "alg" parameter, it must name this algorithm.
	Algorithm httpsig.Algorithm

	// KeyID, if not empty, is the key the signature must use: if the signature has a "keyid" parameter, it must be this.
	KeyID string
}

// FindSignature finds the one signature in the Signature-Input and Signature fields of 'header' whose tag is required.Tag,
// and checks that it meets the requirements. It does not verify the signature — see [Verify].
//
// Other parameters (such as "created") are covered by the signature, but are not checked here.
func FindSignature(header http.Header, required Requirements) (Signature, error) {
	if "" == required.Tag {
		return Signature{}, erorr.Wrap(ErrRequirementsNotMet, "no tag required")
	}

	inputValues := header.Values("Signature-Input")
	signatureValues := header.Values("Signature")
	if 0 == len(inputValues) || 0 == len(signatureValues) {
		return Signature{}, erorr.Wrap(httpsig.ErrSignatureNotFound, "no Signature-Input or Signature field")
	}

	inputs, err := rfc9651.ParseDictionary(strings.Join(inputValues, ", "))
	if nil != err {
		return Signature{}, erorr.Wrap(ErrBadSignatureInput, "Signature-Input is not a Dictionary", field.Error("error", err))
	}
	signatures, err := rfc9651.ParseDictionary(strings.Join(signatureValues, ", "))
	if nil != err {
		return Signature{}, erorr.Wrap(ErrBadSignature, "Signature is not a Dictionary", field.Error("error", err))
	}

	var label string
	var innerList rfc9651.InnerList
	var count int
	for _, member := range inputs {
		candidate, casted := member.Value.(rfc9651.InnerList)
		if !casted {
			continue
		}
		if tag, _ := candidate.Params.Get("tag"); required.Tag != tag {
			continue
		}
		count++
		label = member.Key
		innerList = candidate
	}
	switch count {
	case 0:
		return Signature{}, erorr.Wrap(httpsig.ErrSignatureNotFound, "no signature with the tag", field.String("tag", required.Tag))
	case 1:
		// Nothing here.
	default:
		return Signature{}, erorr.Wrap(ErrTooManySignatures, "more than one signature with the tag", field.String("tag", required.Tag), field.Int("count", count))
	}

	params, err := ParseSignatureParams(innerList)
	if nil != err {
		return Signature{}, err
	}

	member, found := signatures.Get(label)
	if !found {
		return Signature{}, erorr.Wrap(httpsig.ErrSignatureNotFound, "no Signature member for the label", field.String("label", label))
	}
	item, casted := member.(rfc9651.Item)
	if !casted || 0 != len(item.Params) {
		return Signature{}, erorr.Wrap(ErrBadSignature, "Signature member must be a Byte Sequence without parameters", field.String("label", label))
	}
	value, casted := item.Value.([]byte)
	if !casted {
		return Signature{}, erorr.Wrap(ErrBadSignature, "Signature member must be a Byte Sequence", field.String("label", label))
	}

	if err := checkRequirements(params, required); nil != err {
		return Signature{}, err
	}

	return Signature{Label: label, Params: params, Value: value}, nil
}

func checkRequirements(params SignatureParams, required Requirements) error {
	if len(required.Components) != len(params.Components) {
		return erorr.Wrap(ErrRequirementsNotMet, "signature does not cover exactly the required components", field.Int("covered", len(params.Components)), field.Int("required", len(required.Components)))
	}
	for index, component := range params.Components {
		actual, err := component.serialize()
		if nil != err {
			return err
		}
		expected, err := required.Components[index].serialize()
		if nil != err {
			return err
		}
		if expected != actual {
			return erorr.Wrap(ErrRequirementsNotMet, "signature does not cover exactly the required components, in order", field.String("covered", actual), field.String("required", expected))
		}
	}

	if alg, found := params.Alg(); found && string(required.Algorithm) != alg {
		return erorr.Wrap(ErrRequirementsNotMet, "signature algorithm is not the required one", field.String("alg", alg), field.String("required", string(required.Algorithm)))
	}
	if keyID, found := params.KeyID(); found && "" != required.KeyID && required.KeyID != keyID {
		return erorr.Wrap(ErrRequirementsNotMet, "signature keyid is not the required one", field.String("keyid", keyID), field.String("required", required.KeyID))
	}

	return nil
}

// Verify finds the signature on 'message' that meets the requirements (see [FindSignature]), and verifies it with 'key' (see [VerifyBase]).
// It returns the verified signature — so its parameters (such as "created" and "expires") can be checked.
//
// Example usage:
//
//	signature, err := rfc9421.Verify(rfc9421.RequestMessage(r), rfc9421.Requirements{
//		Tag:        "example",
//		Components: []rfc9421.Component{{Name: "@method"}, {Name: "@authority"}, {Name: "content-digest"}},
//		Algorithm:  httpsig.AlgorithmECDSAP256SHA256,
//	}, publicKey)
func Verify(message Message, required Requirements, key any) (Signature, error) {
	signature, err := FindSignature(message.Header, required)
	if nil != err {
		return Signature{}, err
	}

	base, err := SignatureBase(message, signature.Params)
	if nil != err {
		return Signature{}, err
	}

	if err := VerifyBase(required.Algorithm, key, base, signature.Value); nil != err {
		return Signature{}, err
	}

	return signature, nil
}

// Signed holds a new signature's fields: a Signature-Input member and a Signature member, under the same label.
type Signed struct {
	SignatureInput string // ex: sig1=("@method" "@authority");created=1618884473;keyid="test-key"
	Signature      string // ex: sig1=:MEUCIQDX…:
}

// AddTo adds the signature's fields to 'header'.
// (Other signatures already there are kept: a field with more than one line is read as one Dictionary.)
func (receiver Signed) AddTo(header http.Header) {
	header.Add("Signature-Input", receiver.SignatureInput)
	header.Add("Signature", receiver.Signature)
}

// Sign signs 'message', covering what 'params' says, with the algorithm 'algorithm' and the key 'key' (see [SignBase]).
// It returns the Signature-Input and Signature members, under the label 'label'.
//
// Example usage:
//
//	signed, err := rfc9421.Sign(rfc9421.RequestMessage(r), "sig1", rfc9421.SignatureParams{
//		Components: []rfc9421.Component{{Name: "@method"}, {Name: "@authority"}},
//		Params:     rfc9651.Params{{Key: "created", Value: time.Now().Unix()}, {Key: "keyid", Value: "my-key"}},
//	}, httpsig.AlgorithmEd25519, privateKey)
//	if nil != err {
//		return err
//	}
//	signed.AddTo(r.Header)
func Sign(message Message, label string, params SignatureParams, algorithm httpsig.Algorithm, key any) (Signed, error) {
	if alg, found := params.Alg(); found && string(algorithm) != alg {
		return Signed{}, erorr.Wrap(ErrBadSignatureParams, "alg parameter does not name the signing algorithm", field.String("alg", alg), field.String("algorithm", string(algorithm)))
	}

	base, err := SignatureBase(message, params)
	if nil != err {
		return Signed{}, err
	}

	value, err := SignBase(algorithm, key, base)
	if nil != err {
		return Signed{}, err
	}

	signatureInput, err := params.Member(label)
	if nil != err {
		return Signed{}, err
	}
	signature, err := serializeDictionaryMember(label, rfc9651.Item{Value: value})
	if nil != err {
		return Signed{}, err
	}

	return Signed{SignatureInput: signatureInput, Signature: signature}, nil
}
