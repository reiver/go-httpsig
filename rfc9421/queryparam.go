package rfc9421

import (
	"strings"

	"codeberg.org/reiver/go-erorr"
	"codeberg.org/reiver/go-field"
)

// queryParamValue returns the encoded value of the query parameter whose encoded name is 'encodedName' (RFC 9421 §2.2.8).
//
// The query is parsed as application/x-www-form-urlencoded, and each name and value is re-encoded —
// so that, for example, both "a+b" and "a%20b" give "a%20b".
// A parameter that occurs more than once must not be covered, so it is an error.
func queryParamValue(rawQuery string, encodedName string) (string, error) {
	var value string
	var count int

	for _, sequence := range strings.Split(rawQuery, "&") {
		if "" == sequence {
			continue
		}

		name, val, _ := strings.Cut(sequence, "=")
		if encodedName != formEncode(formDecode(name)) {
			continue
		}

		count++
		value = formEncode(formDecode(val))
	}

	switch count {
	case 0:
		return "", erorr.Wrap(ErrComponentNotFound, "query parameter not found", field.String("name", encodedName))
	case 1:
		return value, nil
	default:
		return "", erorr.Wrap(ErrBadComponent, "query parameter occurs more than once", field.String("name", encodedName), field.Int("count", count))
	}
}

// formDecode decodes as application/x-www-form-urlencoded does: "+" is a space, and %XX is a byte.
// (A "%" not followed by 2 hex digits is kept as it is.)
func formDecode(s string) string {
	var builder strings.Builder
	for index := 0; index < len(s); index++ {
		var c byte = s[index]
		switch {
		case '+' == c:
			builder.WriteByte(' ')
		case '%' == c && index+2 < len(s) && isHex(s[index+1]) && isHex(s[index+2]):
			builder.WriteByte(hexValue(s[index+1])<<4 | hexValue(s[index+2]))
			index += 2
		default:
			builder.WriteByte(c)
		}
	}
	return builder.String()
}

// formEncode percent-encodes every byte except ASCII alphanumerics, "*", "-", ".", and "_" (with upper-case hex) —
// the application/x-www-form-urlencoded percent-encode set, but with a space as %20 (not "+").
func formEncode(s string) string {
	const hex = "0123456789ABCDEF"

	var builder strings.Builder
	for index := 0; index < len(s); index++ {
		var c byte = s[index]
		if ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') || '*' == c || '-' == c || '.' == c || '_' == c {
			builder.WriteByte(c)
			continue
		}
		builder.WriteByte('%')
		builder.WriteByte(hex[c>>4])
		builder.WriteByte(hex[c&0x0f])
	}
	return builder.String()
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func hexValue(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
