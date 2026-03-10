package cavage

import (
	"fmt"
	"net/http"
	"strings"

	"codeberg.org/reiver/go-erorr"
	"codeberg.org/reiver/go-field"
)

const (
	ErrCreatedTimeStampNotFound  = erorr.Error("cavage: (created) requested but no created timestamp provided")
	ErrExpiresTimeStampNotFound  = erorr.Error("cavage: (expires) requested but no expires timestamp provided")
	ErrEmptyHeadersList          = erorr.Error("cavage: empty headers list")
	ErrHTTPRequestHeaderNotFound = erorr.Error("cavage: HTTP request header not found")
)

// SigningString constructs the signing string for an HTTP-request, as per draft-cavage-http-signatures-12.
//
// The headers parameter is an ordered list of (lower-cased) HTTP-header names and pseudo-headers to include.
//
// The supported pseudo-headers are:
//
//	• (request-target) — the (lower-cased) HTTP method and request path+query
//	• (created) — the signature creation Unix timestamp
//	• (expires) — the signature expiration Unix timestamp
//
// Each line in the signing string is formatted as:
//
//	lower-case-name: value
//
// Lines are joined by a single newline ("\n").
// There is no trailing newline.
func SigningString(httprequest *http.Request, created, expires int64, headers ...string) (string, error) {
	if 0 == len(headers) {
		var nada string
		return nada, ErrEmptyHeadersList
	}

	var buffer [512]byte
	var p []byte = buffer[0:0]

	for index, header := range headers {
		if 0 < index {
			p = append(p, "\n"...)
		}

		var err error
		p, err = appendSigningStringLine(p, httprequest, header, created, expires)
		if nil != err {
			var nada string
			return nada, err
		}
	}

	return string(p), nil
}

func appendSigningStringLine(p []byte, httprequest *http.Request, header string, created, expires int64) ([]byte, error) {
	header = strings.ToLower(strings.TrimSpace(header))

	switch header {
	case PseudoHeaderRequestTarget:
		return appendRequestTargetLine(p, httprequest), nil

	case PseudoHeaderCreated:
		if 0 == created {
			return p, ErrCreatedTimeStampNotFound
		}
		return appendKeyValue(p, PseudoHeaderCreated, fmt.Sprintf("%d", created)), nil

	case PseudoHeaderExpires:
		if 0 == expires {
			return p, ErrExpiresTimeStampNotFound
		}
		return appendKeyValue(p, PseudoHeaderExpires, fmt.Sprintf("%d", expires)), nil

	default:
		values := httprequest.Header.Values(http.CanonicalHeaderKey(header))
		if 0 == len(values) {
			var err error = ErrHTTPRequestHeaderNotFound
			err = erorr.Wrap(err, "cavage: header not present in request",
				field.String("http-header-name", header),
			)

			return p, err
		}
		// Per the specification, multiple values for the same header are joined with ", ".
		combined := strings.Join(values, ", ")
		return appendKeyValue(p, header, combined), nil
	}
}
