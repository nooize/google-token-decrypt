package gpay

import (
	"fmt"
	"strconv"
)

const (
	PanOnly       AuthMethod = "PAN_ONLY"
	Cryptogram3ds AuthMethod = "CRYPTOGRAM_3DS"
)

type AuthMethod string

func (m *AuthMethod) String() string {
	return string(*m)
}

func (m *AuthMethod) UnmarshalJSON(bytes []byte) error {
	str, _ := strconv.Unquote(string(bytes))
	switch AuthMethod(str) {
	case PanOnly:
	case Cryptogram3ds:
	default:
		return fmt.Errorf("token auth method %v not supported", str)
	}
	*m = AuthMethod(str)
	return nil
}
