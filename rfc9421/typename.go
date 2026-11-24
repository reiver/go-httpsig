package rfc9421

import (
	"fmt"
)

func typeName(value any) string {
	return fmt.Sprintf("%T", value)
}
