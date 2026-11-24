package rfc9421_test

import (
	"bufio"
	"strings"
)

func bufioReader(s string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(s))
}
