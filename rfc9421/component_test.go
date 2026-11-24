package rfc9421_test

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/reiver/go-rfc9651"

	"github.com/reiver/go-httpsig/rfc9421"
)

// componentLine returns the signature base line for one component — the base, minus its "@signature-params" line.
func componentLine(t *testing.T, message rfc9421.Message, component rfc9421.Component) (string, error) {
	t.Helper()

	base, err := rfc9421.SignatureBase(message, rfc9421.SignatureParams{Components: []rfc9421.Component{component}})
	if nil != err {
		return "", err
	}
	line, _, _ := strings.Cut(string(base), "\n")
	return line, nil
}

func sf() rfc9651.Params {
	return rfc9651.Params{{Key: "sf", Value: true}}
}

// The examples of RFC 9421 §2.1, §2.1.1, §2.1.2, and §2.1.3.
func TestFieldComponents_rfcExamples(t *testing.T) {
	var header http.Header = http.Header{}
	header.Add("Host", "www.example.com")
	header.Add("Date", "Tue, 20 Apr 2021 02:07:56 GMT")
	header.Add("X-OWS-Header", "   Leading and trailing whitespace.   ")
	header.Add("X-Obs-Fold-Header", "Obsolete\r\n    line folding.")
	header.Add("Cache-Control", "max-age=60")
	header.Add("Cache-Control", "   must-revalidate")
	header.Add("Example-Dict", " a=1,    b=2;x=1;y=2,   c=(a   b   c)")
	header.Add("X-Empty-Header", "")
	header.Add("Example-Header", "value, with, lots")
	header.Add("Example-Header", "of, commas")
	header.Add("Example-Single", "value, with, lots, of, commas")

	var message rfc9421.Message = rfc9421.Message{
		Header:     header,
		Method:     "GET",
		URL:        &url.URL{Scheme: "https", Host: "www.example.com", Path: "/"},
		FieldTypes: map[string]rfc9421.FieldType{"example-dict": rfc9421.FieldTypeDictionary},
	}

	tests := []struct {
		Component rfc9421.Component
		Expected  string
	}{
		{Component: rfc9421.Component{Name: "host"}, Expected: `"host": www.example.com`},
		{Component: rfc9421.Component{Name: "date"}, Expected: `"date": Tue, 20 Apr 2021 02:07:56 GMT`},
		{Component: rfc9421.Component{Name: "x-ows-header"}, Expected: `"x-ows-header": Leading and trailing whitespace.`},
		{Component: rfc9421.Component{Name: "x-obs-fold-header"}, Expected: `"x-obs-fold-header": Obsolete line folding.`},
		{Component: rfc9421.Component{Name: "cache-control"}, Expected: `"cache-control": max-age=60, must-revalidate`},
		{Component: rfc9421.Component{Name: "example-dict"}, Expected: `"example-dict": a=1,    b=2;x=1;y=2,   c=(a   b   c)`},
		{Component: rfc9421.Component{Name: "x-empty-header"}, Expected: `"x-empty-header": `},
		{Component: rfc9421.Component{Name: "example-dict", Params: sf()}, Expected: `"example-dict";sf: a=1, b=2;x=1;y=2, c=(a b c)`},
		{Component: rfc9421.Component{Name: "example-dict", Params: rfc9651.Params{{Key: "key", Value: "a"}}}, Expected: `"example-dict";key="a": 1`},
		{Component: rfc9421.Component{Name: "example-dict", Params: rfc9651.Params{{Key: "key", Value: "b"}}}, Expected: `"example-dict";key="b": 2;x=1;y=2`},
		{Component: rfc9421.Component{Name: "example-dict", Params: rfc9651.Params{{Key: "key", Value: "c"}}}, Expected: `"example-dict";key="c": (a b c)`},
		{Component: rfc9421.Component{Name: "example-header", Params: rfc9651.Params{{Key: "bs", Value: true}}}, Expected: `"example-header";bs: :dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:`},
		{Component: rfc9421.Component{Name: "example-single", Params: rfc9651.Params{{Key: "bs", Value: true}}}, Expected: `"example-single";bs: :dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:`},
	}

	for _, test := range tests {
		actual, err := componentLine(t, message, test.Component)
		if nil != err {
			t.Errorf("For %s, did not expect an error but actually got one: (%T) %s", test.Component, err, err)
			continue
		}
		if test.Expected != actual {
			t.Errorf("For %s, expected %q but actually got %q.", test.Component, test.Expected, actual)
		}
	}

	// "d" (a Boolean true member) is serialized as ?1.
	header.Set("Example-Dict", "a=1, b=2;x=1;y=2, c=(a   b    c), d")
	if actual, err := componentLine(t, message, rfc9421.Component{Name: "example-dict", Params: rfc9651.Params{{Key: "key", Value: "d"}}}); nil != err || `"example-dict";key="d": ?1` != actual {
		t.Errorf("Unexpected %q (error: %v).", actual, err)
	}
}

// The examples of RFC 9421 §2.2.
func TestDerivedComponents_rfcExamples(t *testing.T) {
	request := func(method string, rawURL string) rfc9421.Message {
		u, err := url.Parse(rawURL)
		if nil != err {
			t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
		}
		return rfc9421.Message{Header: http.Header{}, Method: method, URL: u}
	}

	tests := []struct {
		Message   rfc9421.Message
		Component rfc9421.Component
		Expected  string
	}{
		{Message: request("POST", "https://www.example.com/path?param=value"), Component: rfc9421.Component{Name: "@method"}, Expected: `"@method": POST`},
		{Message: request("post", "https://www.example.com/path"), Component: rfc9421.Component{Name: "@method"}, Expected: `"@method": post`},
		{Message: request("POST", "https://www.example.com/path?param=value"), Component: rfc9421.Component{Name: "@target-uri"}, Expected: `"@target-uri": https://www.example.com/path?param=value`},
		{Message: request("POST", "https://WWW.Example.COM:443/path?param=value"), Component: rfc9421.Component{Name: "@authority"}, Expected: `"@authority": www.example.com`},
		{Message: request("POST", "http://www.example.com:8080/path"), Component: rfc9421.Component{Name: "@authority"}, Expected: `"@authority": www.example.com:8080`},
		{Message: request("POST", "HTTP://www.example.com/path?param=value"), Component: rfc9421.Component{Name: "@scheme"}, Expected: `"@scheme": http`},
		{Message: request("POST", "https://www.example.com/path?param=value"), Component: rfc9421.Component{Name: "@request-target"}, Expected: `"@request-target": /path?param=value`},
		{Message: request("GET", "https://www.example.com/path?param=value"), Component: rfc9421.Component{Name: "@path"}, Expected: `"@path": /path`},
		{Message: request("GET", "https://www.example.com"), Component: rfc9421.Component{Name: "@path"}, Expected: `"@path": /`},
		{Message: request("GET", "https://www.example.com/path?param=value&foo=bar&baz=bat%2Dman"), Component: rfc9421.Component{Name: "@query"}, Expected: `"@query": ?param=value&foo=bar&baz=bat%2Dman`},
		{Message: request("POST", "https://www.example.com/path?queryString"), Component: rfc9421.Component{Name: "@query"}, Expected: `"@query": ?queryString`},
		{Message: request("GET", "https://www.example.com/path"), Component: rfc9421.Component{Name: "@query"}, Expected: `"@query": ?`},
		{Message: request("GET", "https://www.example.com/path?param=value&foo=bar&baz=batman&qux="), Component: rfc9421.Component{Name: "@query-param", Params: rfc9651.Params{{Key: "name", Value: "baz"}}}, Expected: `"@query-param";name="baz": batman`},
		{Message: request("GET", "https://www.example.com/path?param=value&foo=bar&baz=batman&qux="), Component: rfc9421.Component{Name: "@query-param", Params: rfc9651.Params{{Key: "name", Value: "qux"}}}, Expected: `"@query-param";name="qux": `},
		{Message: request("GET", "https://www.example.com/path?param=value&foo=bar&baz=batman&qux="), Component: rfc9421.Component{Name: "@query-param", Params: rfc9651.Params{{Key: "name", Value: "param"}}}, Expected: `"@query-param";name="param": value`},
		{Message: request("GET", "https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something"), Component: rfc9421.Component{Name: "@query-param", Params: rfc9651.Params{{Key: "name", Value: "var"}}}, Expected: `"@query-param";name="var": this%20is%20a%20big%0Amultiline%20value`},
		{Message: request("GET", "https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something"), Component: rfc9421.Component{Name: "@query-param", Params: rfc9651.Params{{Key: "name", Value: "bar"}}}, Expected: `"@query-param";name="bar": with%20plus%20whitespace`},
		{Message: request("GET", "https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something"), Component: rfc9421.Component{Name: "@query-param", Params: rfc9651.Params{{Key: "name", Value: "fa%C3%A7ade%22%3A%20"}}}, Expected: `"@query-param";name="fa%C3%A7ade%22%3A%20": something`},
		{Message: rfc9421.Message{Header: http.Header{}, Status: 200}, Component: rfc9421.Component{Name: "@status"}, Expected: `"@status": 200`},
	}

	for _, test := range tests {
		actual, err := componentLine(t, test.Message, test.Component)
		if nil != err {
			t.Errorf("For %s, did not expect an error but actually got one: (%T) %s", test.Component, err, err)
			continue
		}
		if test.Expected != actual {
			t.Errorf("For %s, expected %q but actually got %q.", test.Component, test.Expected, actual)
		}
	}
}

// On the server side, a request's URL has no scheme or host.
func TestRequestMessage_serverSide(t *testing.T) {
	r, err := http.ReadRequest(bufioReader("GET /path?param=value HTTP/1.1\r\nHost: www.example.com\r\n\r\n"))
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}

	var message rfc9421.Message = rfc9421.RequestMessage(r)

	tests := map[string]string{
		"@target-uri":     `"@target-uri": http://www.example.com/path?param=value`,
		"@authority":      `"@authority": www.example.com`,
		"@scheme":         `"@scheme": http`,
		"@request-target": `"@request-target": /path?param=value`,
	}
	for name, expected := range tests {
		if actual, err := componentLine(t, message, rfc9421.Component{Name: name}); nil != err || expected != actual {
			t.Errorf("For %s, expected %q but actually got %q (error: %v).", name, expected, actual, err)
		}
	}
}

func TestSignatureBase_errors(t *testing.T) {
	var header http.Header = http.Header{}
	header.Set("Example-Dict", "a=1")
	header.Set("Not-A-Dict", "(((")
	header.Set("Non-Ascii", "caf\xc3\xa9")

	var message rfc9421.Message = rfc9421.Message{
		Header:     header,
		Method:     "GET",
		URL:        &url.URL{Scheme: "https", Host: "example.com", Path: "/", RawQuery: "a=1&a=2&b=3"},
		FieldTypes: map[string]rfc9421.FieldType{"example-dict": rfc9421.FieldTypeDictionary, "not-a-dict": rfc9421.FieldTypeDictionary},
	}

	tests := []struct {
		Name       string
		Components []rfc9421.Component
		Expected   error
	}{
		{Name: "duplicate", Components: []rfc9421.Component{{Name: "example-dict"}, {Name: "example-dict"}}, Expected: rfc9421.ErrDuplicateComponent},
		{Name: "duplicate, parameters reordered", Components: []rfc9421.Component{
			{Name: "example-dict", Params: rfc9651.Params{{Key: "sf", Value: true}, {Key: "key", Value: "a"}}},
			{Name: "example-dict", Params: rfc9651.Params{{Key: "key", Value: "a"}, {Key: "sf", Value: true}}},
		}, Expected: rfc9421.ErrDuplicateComponent},
		{Name: "missing field", Components: []rfc9421.Component{{Name: "missing"}}, Expected: rfc9421.ErrComponentNotFound},
		{Name: "upper-case field name", Components: []rfc9421.Component{{Name: "Example-Dict"}}, Expected: rfc9421.ErrBadComponent},
		{Name: "missing dictionary key", Components: []rfc9421.Component{{Name: "example-dict", Params: rfc9651.Params{{Key: "key", Value: "z"}}}}, Expected: rfc9421.ErrComponentNotFound},
		{Name: "not a dictionary", Components: []rfc9421.Component{{Name: "not-a-dict", Params: rfc9651.Params{{Key: "key", Value: "a"}}}}, Expected: rfc9421.ErrComponentNotFound},
		{Name: "sf on a bad structured field", Components: []rfc9421.Component{{Name: "not-a-dict", Params: sf()}}, Expected: rfc9421.ErrComponentNotFound},
		{Name: "sf on a field of unknown type", Components: []rfc9421.Component{{Name: "non-ascii", Params: sf()}}, Expected: rfc9421.ErrUnknownFieldType},
		{Name: "bs with sf", Components: []rfc9421.Component{{Name: "example-dict", Params: rfc9651.Params{{Key: "bs", Value: true}, {Key: "sf", Value: true}}}}, Expected: rfc9421.ErrBadComponent},
		{Name: "sf not true", Components: []rfc9421.Component{{Name: "example-dict", Params: rfc9651.Params{{Key: "sf", Value: false}}}}, Expected: rfc9421.ErrBadComponent},
		{Name: "unknown parameter", Components: []rfc9421.Component{{Name: "example-dict", Params: rfc9651.Params{{Key: "zzz", Value: true}}}}, Expected: rfc9421.ErrBadComponent},
		{Name: "req", Components: []rfc9421.Component{{Name: "example-dict", Params: rfc9651.Params{{Key: "req", Value: true}}}}, Expected: rfc9421.ErrUnsupportedComponent},
		{Name: "tr", Components: []rfc9421.Component{{Name: "example-dict", Params: rfc9651.Params{{Key: "tr", Value: true}}}}, Expected: rfc9421.ErrUnsupportedComponent},
		{Name: "unknown derived component", Components: []rfc9421.Component{{Name: "@zzz"}}, Expected: rfc9421.ErrUnsupportedComponent},
		{Name: "@status on a request", Components: []rfc9421.Component{{Name: "@status"}}, Expected: rfc9421.ErrBadComponent},
		{Name: "@query-param without name", Components: []rfc9421.Component{{Name: "@query-param"}}, Expected: rfc9421.ErrBadComponent},
		{Name: "@query-param repeated", Components: []rfc9421.Component{{Name: "@query-param", Params: rfc9651.Params{{Key: "name", Value: "a"}}}}, Expected: rfc9421.ErrBadComponent},
		{Name: "@query-param missing", Components: []rfc9421.Component{{Name: "@query-param", Params: rfc9651.Params{{Key: "name", Value: "c"}}}}, Expected: rfc9421.ErrComponentNotFound},
		{Name: "non-ASCII", Components: []rfc9421.Component{{Name: "non-ascii"}}, Expected: rfc9421.ErrNotASCII},
	}

	for _, test := range tests {
		_, err := rfc9421.SignatureBase(message, rfc9421.SignatureParams{Components: test.Components})
		if !errors.Is(err, test.Expected) {
			t.Errorf("For %q, expected %v but actually got: %v", test.Name, test.Expected, err)
		}
	}

	// A derived request component on a response.
	if _, err := rfc9421.SignatureBase(rfc9421.Message{Header: http.Header{}, Status: 200}, rfc9421.SignatureParams{Components: []rfc9421.Component{{Name: "@method"}}}); !errors.Is(err, rfc9421.ErrBadComponent) {
		t.Errorf("Expected ErrBadComponent but actually got: %v", err)
	}

	// A signature parameter of the wrong type.
	if _, err := rfc9421.SignatureBase(message, rfc9421.SignatureParams{Params: rfc9651.Params{{Key: "created", Value: "yesterday"}}}); !errors.Is(err, rfc9421.ErrBadSignatureParams) {
		t.Errorf("Expected ErrBadSignatureParams but actually got: %v", err)
	}
}
