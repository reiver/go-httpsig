package cavage

// appendKeyValue appends key and value pair in draft-cavage style HTTP-header form.
//
// For example, if appendKeyValue was called as:
//
//	p = appendKeyValue(p, "banana", "two")
//
// Then what would logically be appended to `p` is:
//
//	[]byte("banana: two")
func appendKeyValue(p []byte, key string, value string) []byte {
	p = append(p , key...)
	p = append(p, ": "...)
	p = append(p , value...)

	return p
}
