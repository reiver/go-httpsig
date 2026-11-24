package rfc9421

import (
	"net/textproto"
	"strconv"
	"strings"

	"codeberg.org/reiver/go-erorr"
	"codeberg.org/reiver/go-field"
	"github.com/reiver/go-rfc9651"
)

// SignatureBase returns the signature base (RFC 9421 §2.5) for a signature with the parameters 'params' over 'message' —
// the bytes that are signed, and verified.
//
// For example:
//
//	"@method": POST
//	"@authority": example.com
//	"content-type": application/json
//	"@signature-params": ("@method" "@authority" "content-type");created=1618884473;keyid="test-key"
func SignatureBase(message Message, params SignatureParams) ([]byte, error) {
	signatureParams, err := params.Serialize()
	if nil != err {
		return nil, err
	}

	var builder strings.Builder
	var seen map[string]struct{} = map[string]struct{}{}

	for _, component := range params.Components {
		identity, err := component.identity()
		if nil != err {
			return nil, err
		}
		if _, found := seen[identity]; found {
			return nil, erorr.Wrap(ErrDuplicateComponent, "component identifier covered more than once", field.String("component", identity))
		}
		seen[identity] = struct{}{}

		identifier, err := component.serialize()
		if nil != err {
			return nil, err
		}

		value, err := componentValue(message, component)
		if nil != err {
			return nil, err
		}
		if strings.ContainsAny(value, "\r\n") {
			return nil, erorr.Wrap(ErrBadComponent, "component value contains a newline", field.String("component", identifier))
		}

		builder.WriteString(identifier)
		builder.WriteString(": ")
		builder.WriteString(value)
		builder.WriteByte('\n')
	}

	builder.WriteString(`"@signature-params": `)
	builder.WriteString(signatureParams)

	var base string = builder.String()
	for index := 0; index < len(base); index++ {
		if 0x80 <= base[index] {
			return nil, erorr.Wrap(ErrNotASCII, "signature base is not ASCII", field.Int("offset", index))
		}
	}

	return []byte(base), nil
}

func componentValue(message Message, component Component) (string, error) {
	if component.isDerived() {
		return derivedComponentValue(message, component)
	}
	return fieldComponentValue(message, component)
}

// RFC 9421 §2.1
func fieldComponentValue(message Message, component Component) (string, error) {
	if component.Name != strings.ToLower(component.Name) || "" == component.Name {
		return "", erorr.Wrap(ErrBadComponent, "an HTTP field component name must be lower-case", field.String("name", component.Name))
	}

	var sf, bs bool
	var key string
	var hasKey bool
	for _, param := range component.Params {
		var err error
		switch param.Key {
		case "sf":
			sf, err = component.flag("sf")
		case "bs":
			bs, err = component.flag("bs")
		case "key":
			key, hasKey, err = component.stringParam("key")
		case "req", "tr":
			return "", erorr.Wrap(ErrUnsupportedComponent, "component parameter not supported", field.String("name", component.Name), field.String("parameter", param.Key))
		default:
			return "", erorr.Wrap(ErrBadComponent, "unknown component parameter", field.String("name", component.Name), field.String("parameter", param.Key))
		}
		if nil != err {
			return "", err
		}
	}
	if bs && (sf || hasKey) {
		return "", erorr.Wrap(ErrBadComponent, "the bs parameter cannot be used with sf or key", field.String("name", component.Name))
	}

	values, found := message.Header[textproto.CanonicalMIMEHeaderKey(component.Name)]
	if !found {
		return "", erorr.Wrap(ErrComponentNotFound, "HTTP field not found", field.String("name", component.Name))
	}

	var lines []string
	for _, value := range values {
		lines = append(lines, canonicalFieldLine(value))
	}

	switch {
	case bs:
		var list rfc9651.List = rfc9651.List{}
		for _, line := range lines {
			list = append(list, rfc9651.Item{Value: []byte(line)})
		}
		return list.Serialize()

	case hasKey:
		dictionary, err := rfc9651.ParseDictionary(strings.Join(lines, ", "))
		if nil != err {
			return "", erorr.Wrap(ErrComponentNotFound, "HTTP field is not a Dictionary", field.String("name", component.Name), field.Error("error", err))
		}
		member, found := dictionary.Get(key)
		if !found {
			return "", erorr.Wrap(ErrComponentNotFound, "Dictionary member not found", field.String("name", component.Name), field.String("key", key))
		}
		// A list of one member serializes exactly as that member.
		return rfc9651.List{member}.Serialize()

	case sf:
		return strictlySerialized(message, component.Name, strings.Join(lines, ", "))

	default:
		return strings.Join(lines, ", "), nil
	}
}

// canonicalFieldLine strips leading and trailing whitespace from a field line, and replaces obsolete line folding with a single space.
func canonicalFieldLine(value string) string {
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		var c byte = value[index]
		if '\r' == c || '\n' == c {
			// obs-fold = OWS CRLF RWS
			for index+1 < len(value) && isWhitespace(value[index+1]) {
				index++
			}
			trimmed := strings.TrimRight(builder.String(), " \t")
			builder.Reset()
			builder.WriteString(trimmed)
			builder.WriteByte(' ')
			continue
		}
		builder.WriteByte(c)
	}
	return strings.Trim(builder.String(), " \t")
}

func isWhitespace(c byte) bool {
	return ' ' == c || '\t' == c || '\r' == c || '\n' == c
}

// RFC 9421 §2.1.1
func strictlySerialized(message Message, name string, value string) (string, error) {
	fieldType, found := message.FieldTypes[name]
	if !found {
		return "", erorr.Wrap(ErrUnknownFieldType, "Structured Field type of the field not known", field.String("name", name))
	}

	var serialized string
	var err error
	switch fieldType {
	case FieldTypeItem:
		var item rfc9651.Item
		item, err = rfc9651.ParseItem(value)
		if nil == err {
			serialized, err = item.Serialize()
		}
	case FieldTypeList:
		var list rfc9651.List
		list, err = rfc9651.ParseList(value)
		if nil == err {
			serialized, err = list.Serialize()
		}
	case FieldTypeDictionary:
		var dictionary rfc9651.Dictionary
		dictionary, err = rfc9651.ParseDictionary(value)
		if nil == err {
			serialized, err = dictionary.Serialize()
		}
	default:
		return "", erorr.Wrap(ErrUnknownFieldType, "unknown Structured Field type", field.String("name", name), field.Int("type", int(fieldType)))
	}
	if nil != err {
		return "", erorr.Wrap(ErrComponentNotFound, "HTTP field is not a valid Structured Field", field.String("name", name), field.Error("error", err))
	}
	return serialized, nil
}

// RFC 9421 §2.2
func derivedComponentValue(message Message, component Component) (string, error) {
	var queryParamName string
	for _, param := range component.Params {
		switch {
		case "req" == param.Key:
			return "", erorr.Wrap(ErrUnsupportedComponent, "component parameter not supported", field.String("name", component.Name), field.String("parameter", param.Key))
		case "name" == param.Key && "@query-param" == component.Name:
			name, _, err := component.stringParam("name")
			if nil != err {
				return "", err
			}
			queryParamName = name
		default:
			return "", erorr.Wrap(ErrBadComponent, "unknown component parameter", field.String("name", component.Name), field.String("parameter", param.Key))
		}
	}

	if "@status" == component.Name {
		if !message.isResponse() {
			return "", erorr.Wrap(ErrBadComponent, "@status is only for a response")
		}
		if message.Status < 100 || 999 < message.Status {
			return "", erorr.Wrap(ErrComponentNotFound, "bad status code", field.Int("status", message.Status))
		}
		return strconv.Itoa(message.Status), nil
	}

	if message.isResponse() {
		return "", erorr.Wrap(ErrBadComponent, "derived component is only for a request", field.String("name", component.Name))
	}

	var value string
	switch component.Name {
	case "@method":
		value = message.Method
	case "@target-uri":
		if nil == message.URL {
			return "", erorr.Wrap(ErrComponentNotFound, "request has no target URI")
		}
		value = strings.ToLower(message.URL.Scheme) + "://" + authority(message) + requestTarget(message)
	case "@authority":
		value = authority(message)
	case "@scheme":
		if nil == message.URL {
			return "", erorr.Wrap(ErrComponentNotFound, "request has no target URI")
		}
		value = strings.ToLower(message.URL.Scheme)
	case "@request-target":
		if "" != message.RequestTarget {
			value = message.RequestTarget
		} else {
			value = requestTarget(message)
		}
	case "@path":
		if nil == message.URL {
			return "", erorr.Wrap(ErrComponentNotFound, "request has no target URI")
		}
		value = message.URL.EscapedPath()
		if "" == value {
			value = "/"
		}
	case "@query":
		if nil == message.URL {
			return "", erorr.Wrap(ErrComponentNotFound, "request has no target URI")
		}
		value = "?" + message.URL.RawQuery
	case "@query-param":
		if "" == queryParamName {
			return "", erorr.Wrap(ErrBadComponent, "@query-param needs a name parameter")
		}
		if nil == message.URL {
			return "", erorr.Wrap(ErrComponentNotFound, "request has no target URI")
		}
		var err error
		value, err = queryParamValue(message.URL.RawQuery, queryParamName)
		if nil != err {
			return "", err
		}
	default:
		return "", erorr.Wrap(ErrUnsupportedComponent, "unknown derived component", field.String("name", component.Name))
	}

	if "" == value && "@query-param" != component.Name {
		return "", erorr.Wrap(ErrComponentNotFound, "derived component has no value", field.String("name", component.Name))
	}
	for index := 0; index < len(value); index++ {
		if c := value[index]; c < 0x20 || 0x7e < c {
			return "", erorr.Wrap(ErrBadComponent, "derived component value must be printable ASCII", field.String("name", component.Name))
		}
	}
	if strings.Trim(value, " ") != value {
		return "", erorr.Wrap(ErrBadComponent, "derived component value must not start or end with whitespace", field.String("name", component.Name))
	}

	return value, nil
}

// authority returns the request's authority: the host in lower-case, with the port unless it is the scheme's default.
func authority(message Message) string {
	if nil == message.URL {
		return ""
	}

	var host string = strings.ToLower(message.URL.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // IPv6
	}

	var port string = message.URL.Port()
	switch strings.ToLower(message.URL.Scheme) + ":" + port {
	case "http:80", "https:443", "http:", "https:":
		return host
	}
	if "" == port {
		return host
	}
	return host + ":" + port
}

// requestTarget returns the request's path (or "/") and query (with its "?", if there is a query).
func requestTarget(message Message) string {
	if nil == message.URL {
		return ""
	}

	var path string = message.URL.EscapedPath()
	if "" == path {
		path = "/"
	}
	if "" != message.URL.RawQuery || message.URL.ForceQuery {
		return path + "?" + message.URL.RawQuery
	}
	return path
}
