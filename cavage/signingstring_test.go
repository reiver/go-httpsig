package cavage_test

import (
	"net/http"
	"testing"

	"github.com/reiver/go-httpsig/cavage"
)

func TestSigningString(t *testing.T) {
	tests := []struct {
		Name     string
		Method   string
		Path     string
		Headers  map[string]string
		Signed   []string
		Created  int64
		Expires  int64
		Expected string
	}{
		{
			Name:   "request-target only",
			Method: "POST",
			Path:   "/foo",
			Signed: []string{"(request-target)"},
			Expected: "(request-target): post /foo",
		},
		{
			Name:   "request-target with query string",
			Method: "GET",
			Path:   "/foo?bar=baz&qux=1",
			Signed: []string{"(request-target)"},
			Expected: "(request-target): get /foo?bar=baz&qux=1",
		},
		{
			Name:   "single header",
			Method: "GET",
			Path:   "/",
			Headers: map[string]string{
				"Host": "example.org",
			},
			Signed:   []string{"host"},
			Expected: "host: example.org",
		},
		{
			Name:   "multiple headers",
			Method: "POST",
			Path:   "/foo",
			Headers: map[string]string{
				"Host":   "example.org",
				"Date":   "Tue, 07 Jun 2014 20:51:35 GMT",
				"Digest": "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
			},
			Signed: []string{"(request-target)", "host", "date", "digest"},
			Expected: "(request-target): post /foo\n" +
				"host: example.org\n" +
				"date: Tue, 07 Jun 2014 20:51:35 GMT\n" +
				"digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
		},
		{
			Name:   "with created and expires",
			Method: "POST",
			Path:   "/foo",
			Headers: map[string]string{
				"Host": "example.org",
			},
			Signed:  []string{"(request-target)", "(created)", "(expires)", "host"},
			Created: 1402170695,
			Expires: 1402170995,
			Expected: "(request-target): post /foo\n" +
				"(created): 1402170695\n" +
				"(expires): 1402170995\n" +
				"host: example.org",
		},
	}

	for testNumber, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			r, err := http.NewRequest(test.Method, "http://example.org"+test.Path, nil)
			if nil != err {
				t.Errorf("For test #%d, did not expect an error but actually got one.", testNumber)
				t.Logf("ERROR: %s", err)
				return
			}

			for k, v := range test.Headers {
				r.Header.Set(k, v)
			}

			actual, err := cavage.SigningString(r, test.Created, test.Expires, test.Signed...)
			if nil != err {
				t.Errorf("For test #%d, did not expect an error but actually got one.", testNumber)
				t.Logf("ERROR: %s", err)
				return
			}

			expected := test.Expected

			if expected != actual {
				t.Errorf("For test #%d, the actual Signing String is not what was expected.", testNumber)
				t.Logf("EXPECTED:\n%s", expected)
				t.Logf("ACTUAL:\n%s", actual)
				return
			}
		})
	}
}

func TestSigningString_errors(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.org/", nil)

	t.Run("empty headers", func(t *testing.T) {
		_, err := cavage.SigningString(r, 0, 0)
		if err == nil {
			t.Fatal("expected error for empty headers")
		}
	})

	t.Run("missing header", func(t *testing.T) {
		_, err := cavage.SigningString(r, 0, 0, "x-no-such-header")
		if err == nil {
			t.Fatal("expected error for missing header")
		}
	})

	t.Run("created without timestamp", func(t *testing.T) {
		_, err := cavage.SigningString(r, 0, 0, "(created)")
		if err == nil {
			t.Fatal("expected error for (created) without timestamp")
		}
	})

	t.Run("expires without timestamp", func(t *testing.T) {
		_, err := cavage.SigningString(r, 0, 0, "(expires)")
		if err == nil {
			t.Fatal("expected error for (expires) without timestamp")
		}
	})
}
