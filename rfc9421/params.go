package rfc9421

import (
	"codeberg.org/reiver/go-erorr"
	"codeberg.org/reiver/go-field"
	"github.com/reiver/go-rfc9651"
)

// SignatureParams are a signature's parameters: the ordered covered components, and the ordered signature parameters
// (such as "created", "expires", "nonce", "alg", "keyid", and "tag").
//
// Serialized, they are the value of a Signature-Input (or Accept-Signature) member, and the last line of the signature base. For example:
//
//	("@method" "@authority" "content-digest");created=1618884473;keyid="test-key"
type SignatureParams struct {
	Components []Component
	Params     rfc9651.Params
}

// ParseSignatureParams returns the signature parameters held in a Structured Field inner list
// (ex: a member of a parsed Signature-Input field).
func ParseSignatureParams(innerList rfc9651.InnerList) (SignatureParams, error) {
	var params SignatureParams = SignatureParams{Params: innerList.Params}

	for index, item := range innerList.Items {
		name, casted := item.Value.(string)
		if !casted {
			return SignatureParams{}, erorr.Wrap(ErrBadSignatureParams, "covered component name must be a String", field.Int("index", index))
		}
		params.Components = append(params.Components, Component{Name: name, Params: item.Params})
	}

	if err := params.validate(); nil != err {
		return SignatureParams{}, err
	}
	return params, nil
}

// validate checks the types of the signature parameters RFC 9421 defines.
func (receiver SignatureParams) validate() error {
	for _, param := range receiver.Params {
		switch param.Key {
		case "created", "expires":
			if _, casted := param.Value.(int64); !casted {
				if _, casted := param.Value.(int); !casted {
					return erorr.Wrap(ErrBadSignatureParams, "signature parameter must be an Integer", field.String("parameter", param.Key))
				}
			}
		case "nonce", "alg", "keyid", "tag":
			if _, casted := param.Value.(string); !casted {
				return erorr.Wrap(ErrBadSignatureParams, "signature parameter must be a String", field.String("parameter", param.Key))
			}
		}
	}
	return nil
}

// InnerList returns the signature parameters as a Structured Field inner list.
func (receiver SignatureParams) InnerList() rfc9651.InnerList {
	var items []rfc9651.Item = []rfc9651.Item{}
	for _, component := range receiver.Components {
		items = append(items, component.item())
	}
	return rfc9651.InnerList{Items: items, Params: receiver.Params}
}

// Serialize returns the serialized signature parameters (ex: ("@method" "@authority");created=1618884473).
func (receiver SignatureParams) Serialize() (string, error) {
	if err := receiver.validate(); nil != err {
		return "", err
	}

	// A list of one inner list serializes exactly as that inner list.
	s, err := rfc9651.List{receiver.InnerList()}.Serialize()
	if nil != err {
		return "", erorr.Wrap(ErrBadSignatureParams, "signature parameters cannot be serialized", field.Error("error", err))
	}
	return s, nil
}

// Member returns a Signature-Input (or Accept-Signature) member: the label, "=", and the serialized signature parameters
// (ex: sig1=("@method");created=1618884473).
func (receiver SignatureParams) Member(label string) (string, error) {
	return serializeDictionaryMember(label, receiver.InnerList())
}

func serializeDictionaryMember(label string, member rfc9651.Member) (string, error) {
	s, err := rfc9651.Dictionary{{Key: label, Value: member}}.Serialize()
	if nil != err {
		return "", erorr.Wrap(ErrBadSignatureParams, "dictionary member cannot be serialized", field.String("label", label), field.Error("error", err))
	}
	return s, nil
}

func (receiver SignatureParams) stringParam(key string) (string, bool) {
	value, found := receiver.Params.Get(key)
	if !found {
		return "", false
	}
	s, casted := value.(string)
	return s, casted
}

func (receiver SignatureParams) integerParam(key string) (int64, bool) {
	value, found := receiver.Params.Get(key)
	if !found {
		return 0, false
	}
	switch casted := value.(type) {
	case int64:
		return casted, true
	case int:
		return int64(casted), true
	default:
		return 0, false
	}
}

// Created returns the "created" parameter — a UNIX timestamp.
func (receiver SignatureParams) Created() (int64, bool) {
	return receiver.integerParam("created")
}

// Expires returns the "expires" parameter — a UNIX timestamp.
func (receiver SignatureParams) Expires() (int64, bool) {
	return receiver.integerParam("expires")
}

// Nonce returns the "nonce" parameter.
func (receiver SignatureParams) Nonce() (string, bool) {
	return receiver.stringParam("nonce")
}

// Alg returns the "alg" parameter — the signature algorithm (ex: "ecdsa-p256-sha256").
func (receiver SignatureParams) Alg() (string, bool) {
	return receiver.stringParam("alg")
}

// KeyID returns the "keyid" parameter.
func (receiver SignatureParams) KeyID() (string, bool) {
	return receiver.stringParam("keyid")
}

// Tag returns the "tag" parameter — which an application uses to find the signature meant for it.
func (receiver SignatureParams) Tag() (string, bool) {
	return receiver.stringParam("tag")
}
