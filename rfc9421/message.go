package rfc9421

import (
	"net/http"
	"net/url"
)

// FieldType is the Structured Field type of an HTTP field.
type FieldType int

const (
	FieldTypeItem FieldType = iota + 1
	FieldTypeList
	FieldTypeDictionary
)

// Message is the HTTP message a signature is over: a request or a response.
type Message struct {
	// Header holds the message's header fields.
	Header http.Header

	// Method is a request's method (ex: "POST").
	Method string

	// URL is a request's target URI — with its scheme, authority (host), path, and query.
	URL *url.URL

	// RequestTarget is a request's request-target, as in the HTTP/1.1 request line (ex: "/foo?a=b", or "*").
	// If it is empty, it is taken from URL (its path and query).
	RequestTarget string

	// Status is a response's status code (ex: 200). A message with a Status is a response.
	Status int

	// FieldTypes gives the Structured Field type of each field that may be covered with the "sf" parameter (by lower-case field name).
	// (A field covered with the "key" parameter is always a Dictionary.)
	FieldTypes map[string]FieldType
}

// RequestMessage returns the [Message] for an HTTP request — on either the client or the server side.
//
// On the server side, where r.URL has no scheme or host, they are taken from r.TLS and r.Host.
func RequestMessage(r *http.Request) Message {
	var u url.URL
	if nil != r.URL {
		u = *r.URL
	}
	if "" == u.Host {
		u.Host = r.Host
	}
	if "" == u.Scheme {
		if nil != r.TLS {
			u.Scheme = "https"
		} else {
			u.Scheme = "http"
		}
	}

	return Message{
		Header:        r.Header,
		Method:        r.Method,
		URL:           &u,
		RequestTarget: r.RequestURI,
	}
}

// ResponseMessage returns the [Message] for an HTTP response.
func ResponseMessage(r *http.Response) Message {
	return Message{
		Header: r.Header,
		Status: r.StatusCode,
	}
}

func (receiver Message) isResponse() bool {
	return 0 != receiver.Status
}
