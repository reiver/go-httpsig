package rfc9421

import (
	"sort"
	"strings"

	"codeberg.org/reiver/go-erorr"
	"codeberg.org/reiver/go-field"
	"github.com/reiver/go-rfc9651"
)

// Component is a component identifier: a component name (an HTTP field name, in lower-case, or a derived component name, such as "@method")
// with any parameters (such as "sf", "key", "bs", or "name").
//
// Example usage:
//
//	var authorization = rfc9421.Component{Name: "authorization"}
//
//	var commit = rfc9421.Component{Name: "atproto-space-commit", Params: rfc9651.Params{{Key: "sf", Value: true}}}
type Component struct {
	Name   string
	Params rfc9651.Params
}

// item returns the component identifier as a Structured Field item — a String with parameters.
func (receiver Component) item() rfc9651.Item {
	return rfc9651.Item{Value: receiver.Name, Params: receiver.Params}
}

// String returns the serialized component identifier (ex: "content-type", "example-dict";key="a"), or "" if it cannot be serialized.
func (receiver Component) String() string {
	s, err := receiver.serialize()
	if nil != err {
		return ""
	}
	return s
}

func (receiver Component) serialize() (string, error) {
	s, err := receiver.item().Serialize()
	if nil != err {
		return "", erorr.Wrap(ErrBadComponent, "component identifier cannot be serialized", field.String("name", receiver.Name), field.Error("error", err))
	}
	return s, nil
}

// identity returns a string that is the same for two component identifiers if and only if they are equal —
// the same name and the same parameters, in any order.
func (receiver Component) identity() (string, error) {
	var params []string
	for _, param := range receiver.Params {
		s, err := rfc9651.Item{Value: true, Params: rfc9651.Params{param}}.Serialize()
		if nil != err {
			return "", erorr.Wrap(ErrBadComponent, "component parameter cannot be serialized", field.String("name", receiver.Name), field.Error("error", err))
		}
		params = append(params, s)
	}
	sort.Strings(params)

	name, err := rfc9651.Item{Value: receiver.Name}.Serialize()
	if nil != err {
		return "", erorr.Wrap(ErrBadComponent, "component name cannot be serialized", field.String("name", receiver.Name), field.Error("error", err))
	}
	return name + strings.Join(params, ""), nil
}

func (receiver Component) isDerived() bool {
	return strings.HasPrefix(receiver.Name, "@")
}

// flag returns whether the component has the Boolean parameter 'key' — which must be true if present.
func (receiver Component) flag(key string) (bool, error) {
	value, found := receiver.Params.Get(key)
	if !found {
		return false, nil
	}
	if b, casted := value.(bool); !casted || !b {
		return false, erorr.Wrap(ErrBadComponent, "component parameter must be the Boolean true", field.String("name", receiver.Name), field.String("parameter", key))
	}
	return true, nil
}

// stringParam returns the String parameter 'key', if present.
func (receiver Component) stringParam(key string) (string, bool, error) {
	value, found := receiver.Params.Get(key)
	if !found {
		return "", false, nil
	}
	s, casted := value.(string)
	if !casted {
		return "", false, erorr.Wrap(ErrBadComponent, "component parameter must be a String", field.String("name", receiver.Name), field.String("parameter", key))
	}
	return s, true, nil
}
