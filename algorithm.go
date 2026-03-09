package httpsig

// Algorithm represents a signing/verification algorithm for HTTP signatures.
type Algorithm string

const (
	// Algorithms from draft-cavage-http-signatures-12.

	// AlgorithmRSASHA256 is RSASSA-PKCS1-v1_5 with SHA-256.
	// This is the most widely used algorithm in the Fediverse.
	AlgorithmRSASHA256 Algorithm = "rsa-sha256"

	// AlgorithmRSASHA512 is RSASSA-PKCS1-v1_5 with SHA-512.
	AlgorithmRSASHA512 Algorithm = "rsa-sha512"

	// AlgorithmHS2019 is a placeholder that means "determine the algorithm from the key metadata."
	// In practice on the Fediverse, this almost always means RSA-SHA256.
	AlgorithmHS2019 Algorithm = "hs2019"

	// Algorithms from RFC 9421 (also usable with cavage where supported).

	// AlgorithmEd25519 is EdDSA using Curve25519.
	AlgorithmEd25519 Algorithm = "ed25519"

	// AlgorithmECDSAP256SHA256 is ECDSA using curve P-256 with SHA-256.
	AlgorithmECDSAP256SHA256 Algorithm = "ecdsa-p256-sha256"

	// AlgorithmECDSAP384SHA384 is ECDSA using curve P-384 with SHA-384.
	AlgorithmECDSAP384SHA384 Algorithm = "ecdsa-p384-sha384"

	// AlgorithmRSAPSSSHA512 is RSASSA-PSS using SHA-512.
	AlgorithmRSAPSSSHA512 Algorithm = "rsa-pss-sha512"

	// AlgorithmHMACSHA256 is HMAC using SHA-256 (symmetric).
	AlgorithmHMACSHA256 Algorithm = "hmac-sha256"
)
