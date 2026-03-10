package cavage

import (
	"net/http"
	"strings"
)

const (
	PseudoHeaderCreated       = "(created)"
	PseudoHeaderExpires       = "(expires)"
	PseudoHeaderRequestTarget = "(request-target)"
)

// appendRequestTargetLine append the (request-target) pseudo-header line.
//
// The format is:
//
//	"(request-target): method path?query"
//
// For example:
//
//	"(request-target): get /api/v1/users?id=123"
//
// The method is lower-cased.
// The path includes the query string if present.
func appendRequestTargetLine(p []byte, request *http.Request) []byte {
	p = append(p, PseudoHeaderRequestTarget...)
	p = append(p, ": "...)
	p = appendRequestTargetValue(p, request)

	return p
}

// appendRequestTargetValue appends the value of (request-target) for an HTTP-request given by a [http.Request].
//
// appendRequestTargetValue is used by [SigningString].
//
//	get /api/v1/users?id=123
func appendRequestTargetValue(p []byte, request *http.Request) []byte {
	if nil == request {
		return p
	}
	if nil == request.URL {
		return p
	}

	var method string = strings.ToLower(request.Method)

	{
		requri := request.URL.RequestURI()
		if "" != requri {
			p = append(p, method...)
			p = append(p, " "...)
			p = append(p, requri...)

			return p
		}
	}

	{
		var buffer [256]byte
		var requri []byte = buffer[0:0]

		if 0 < len(request.URL.Path) || 0 < len(request.URL.RawQuery) {
			requri = append(requri, request.URL.Path...)
			requri = append(requri, '?')
			requri = append(requri, request.URL.RawQuery...)
		}

		if 0 < len(requri) {
			p = append(p, method...)
			p = append(p, " "...)
			p = append(p, requri...)

			return p
		}
	}

	return p
}
