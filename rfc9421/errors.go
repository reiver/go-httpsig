package rfc9421

import (
	"codeberg.org/reiver/go-erorr"
)

const (
	ErrBadComponent          = erorr.Error("rfc9421: bad component identifier")
	ErrBadSignature          = erorr.Error("rfc9421: bad Signature field")
	ErrBadSignatureInput     = erorr.Error("rfc9421: bad Signature-Input field")
	ErrBadSignatureParams    = erorr.Error("rfc9421: bad signature parameters")
	ErrComponentNotFound     = erorr.Error("rfc9421: component not found in the message")
	ErrDuplicateComponent    = erorr.Error("rfc9421: component identifier covered more than once")
	ErrNotASCII              = erorr.Error("rfc9421: signature base is not ASCII")
	ErrRequirementsNotMet    = erorr.Error("rfc9421: signature does not meet the requirements")
	ErrTooManySignatures     = erorr.Error("rfc9421: more than one signature with the tag")
	ErrUnknownFieldType      = erorr.Error("rfc9421: Structured Field type of the field not known")
	ErrUnsupportedComponent  = erorr.Error("rfc9421: component identifier not supported")
)
