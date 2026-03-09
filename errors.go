package httpsig

import (
	"codeberg.org/reiver/go-erorr"
)

const (
	// ErrAlgorithmNotSupported is returned when the specified algorithm is not supported.
	ErrAlgorithmNotSupported = erorr.Error("httpsig: algorithm not supported")

	// ErrDigestMismatch is returned when the Digest or Content-Digest header does not match the body.
	ErrDigestMismatch = erorr.Error("httpsig: digest mismatch")

	// ErrKeyNotFound is returned when a KeyLookup cannot find a key for the given key ID.
	ErrKeyNotFound = erorr.Error("httpsig: key not found")

	// ErrKeyTypeInvalid is returned when the provided key is not the right type for the algorithm.
	ErrKeyTypeInvalid = erorr.Error("httpsig: invalid key type")

	// ErrRequiredHeaderMissing is returned when a header that must be signed is not present on the message.
	ErrRequiredHeaderMissing = erorr.Error("httpsig: missing required header")

	// ErrSignatureExpired is returned when a signature's timestamp is outside the acceptable window.
	ErrSignatureExpired = erorr.Error("httpsig: signature expired")

	// ErrSignatureNotFound is returned when no signature is present on a message.
	ErrSignatureNotFound = erorr.Error("httpsig: signature not found")

	// ErrSignatureInvalid is returned when a signature fails verification.
	ErrSignatureInvalid = erorr.Error("httpsig: signature invalid")

)
