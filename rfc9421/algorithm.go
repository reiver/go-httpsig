package rfc9421

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"

	"codeberg.org/reiver/go-erorr"
	"codeberg.org/reiver/go-field"

	"github.com/reiver/go-httpsig"
)

// SignBase signs a signature base (from [SignatureBase]) with the algorithm 'algorithm' (RFC 9421 §3.3), and returns the signature.
//
// The key must be, for:
//
//	• hmac-sha256       — the shared secret, as a []byte
//	• ecdsa-p256-sha256 — an *ecdsa.PrivateKey on P-256 (the signature is r‖s, 64 bytes, with a low s)
//	• ecdsa-p384-sha384 — an *ecdsa.PrivateKey on P-384 (the signature is r‖s, 96 bytes, with a low s)
//	• ed25519           — an ed25519.PrivateKey
//	• rsa-pss-sha512    — an *rsa.PrivateKey
//	• rsa-v1_5-sha256   — an *rsa.PrivateKey
func SignBase(algorithm httpsig.Algorithm, key any, base []byte) ([]byte, error) {
	switch algorithm {
	case httpsig.AlgorithmHMACSHA256:
		secret, casted := key.([]byte)
		if !casted {
			return nil, keyTypeError(algorithm, key)
		}
		var mac = hmac.New(sha256.New, secret)
		mac.Write(base)
		return mac.Sum(nil), nil

	case httpsig.AlgorithmECDSAP256SHA256:
		digest := sha256.Sum256(base)
		return signECDSA(algorithm, key, elliptic.P256(), digest[:])

	case httpsig.AlgorithmECDSAP384SHA384:
		digest := sha512.Sum384(base)
		return signECDSA(algorithm, key, elliptic.P384(), digest[:])

	case httpsig.AlgorithmEd25519:
		privateKey, casted := key.(ed25519.PrivateKey)
		if !casted || ed25519.PrivateKeySize != len(privateKey) {
			return nil, keyTypeError(algorithm, key)
		}
		return ed25519.Sign(privateKey, base), nil

	case httpsig.AlgorithmRSAPSSSHA512:
		privateKey, casted := key.(*rsa.PrivateKey)
		if !casted || nil == privateKey {
			return nil, keyTypeError(algorithm, key)
		}
		digest := sha512.Sum512(base)
		return rsa.SignPSS(rand.Reader, privateKey, crypto.SHA512, digest[:], &rsa.PSSOptions{SaltLength: sha512.Size})

	case httpsig.AlgorithmRSAV15SHA256:
		privateKey, casted := key.(*rsa.PrivateKey)
		if !casted || nil == privateKey {
			return nil, keyTypeError(algorithm, key)
		}
		digest := sha256.Sum256(base)
		return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])

	default:
		return nil, erorr.Wrap(httpsig.ErrAlgorithmNotSupported, "signature algorithm not supported", field.String("algorithm", string(algorithm)))
	}
}

// VerifyBase checks a signature over a signature base (from [SignatureBase]) with the algorithm 'algorithm' (RFC 9421 §3.3).
// It returns nil if the signature is valid, and an error matching httpsig.ErrSignatureInvalid if it is not.
//
// The key must be, for:
//
//	• hmac-sha256       — the shared secret, as a []byte (compared in constant time)
//	• ecdsa-p256-sha256 — an *ecdsa.PublicKey on P-256 (the signature is r‖s, 64 bytes; a high s is accepted)
//	• ecdsa-p384-sha384 — an *ecdsa.PublicKey on P-384 (the signature is r‖s, 96 bytes; a high s is accepted)
//	• ed25519           — an ed25519.PublicKey
//	• rsa-pss-sha512    — an *rsa.PublicKey
//	• rsa-v1_5-sha256   — an *rsa.PublicKey
func VerifyBase(algorithm httpsig.Algorithm, key any, base []byte, signature []byte) error {
	var valid bool

	switch algorithm {
	case httpsig.AlgorithmHMACSHA256:
		secret, casted := key.([]byte)
		if !casted {
			return keyTypeError(algorithm, key)
		}
		var mac = hmac.New(sha256.New, secret)
		mac.Write(base)
		valid = hmac.Equal(mac.Sum(nil), signature)

	case httpsig.AlgorithmECDSAP256SHA256:
		digest := sha256.Sum256(base)
		var err error
		valid, err = verifyECDSA(algorithm, key, elliptic.P256(), digest[:], signature)
		if nil != err {
			return err
		}

	case httpsig.AlgorithmECDSAP384SHA384:
		digest := sha512.Sum384(base)
		var err error
		valid, err = verifyECDSA(algorithm, key, elliptic.P384(), digest[:], signature)
		if nil != err {
			return err
		}

	case httpsig.AlgorithmEd25519:
		publicKey, casted := key.(ed25519.PublicKey)
		if !casted || ed25519.PublicKeySize != len(publicKey) {
			return keyTypeError(algorithm, key)
		}
		valid = ed25519.Verify(publicKey, base, signature)

	case httpsig.AlgorithmRSAPSSSHA512:
		publicKey, casted := key.(*rsa.PublicKey)
		if !casted || nil == publicKey {
			return keyTypeError(algorithm, key)
		}
		digest := sha512.Sum512(base)
		valid = nil == rsa.VerifyPSS(publicKey, crypto.SHA512, digest[:], signature, &rsa.PSSOptions{SaltLength: sha512.Size})

	case httpsig.AlgorithmRSAV15SHA256:
		publicKey, casted := key.(*rsa.PublicKey)
		if !casted || nil == publicKey {
			return keyTypeError(algorithm, key)
		}
		digest := sha256.Sum256(base)
		valid = nil == rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature)

	default:
		return erorr.Wrap(httpsig.ErrAlgorithmNotSupported, "signature algorithm not supported", field.String("algorithm", string(algorithm)))
	}

	if !valid {
		return erorr.Wrap(httpsig.ErrSignatureInvalid, "signature invalid", field.String("algorithm", string(algorithm)))
	}
	return nil
}

func keyTypeError(algorithm httpsig.Algorithm, key any) error {
	return erorr.Wrap(httpsig.ErrKeyTypeInvalid, "wrong key type for the signature algorithm", field.String("algorithm", string(algorithm)), field.String("key-type", typeName(key)))
}

func signECDSA(algorithm httpsig.Algorithm, key any, curve elliptic.Curve, digest []byte) ([]byte, error) {
	privateKey, casted := key.(*ecdsa.PrivateKey)
	if !casted || nil == privateKey || curve != privateKey.Curve {
		return nil, keyTypeError(algorithm, key)
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
	if nil != err {
		return nil, err
	}

	// Use the low s (of s and n−s), so the signature is not malleable.
	var n *big.Int = curve.Params().N
	if 0 < s.Cmp(new(big.Int).Rsh(n, 1)) {
		s = new(big.Int).Sub(n, s)
	}

	var size int = (curve.Params().BitSize + 7) / 8
	var signature []byte = make([]byte, 2*size)
	r.FillBytes(signature[:size])
	s.FillBytes(signature[size:])
	return signature, nil
}

func verifyECDSA(algorithm httpsig.Algorithm, key any, curve elliptic.Curve, digest []byte, signature []byte) (bool, error) {
	publicKey, casted := key.(*ecdsa.PublicKey)
	if !casted || nil == publicKey || curve != publicKey.Curve {
		return false, keyTypeError(algorithm, key)
	}

	var size int = (curve.Params().BitSize + 7) / 8
	if 2*size != len(signature) {
		return false, nil
	}

	var r *big.Int = new(big.Int).SetBytes(signature[:size])
	var s *big.Int = new(big.Int).SetBytes(signature[size:])
	return ecdsa.Verify(publicKey, digest, r, s), nil
}
