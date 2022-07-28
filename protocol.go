package gpay

import (
	"fmt"
	"strconv"
)

const (
	EcV1            TokenProtocol = "ECv1"
	EcV2            TokenProtocol = "ECv2"
	EcV2SigningOnly TokenProtocol = "ECv2SigningOnly"
)

type TokenProtocol string

func (p *TokenProtocol) String() string {
	return string(*p)
}

func (p *TokenProtocol) UnmarshalJSON(bytes []byte) error {
	str, _ := strconv.Unquote(string(bytes))
	switch TokenProtocol(str) {
	case EcV1:
	case EcV2:
	case EcV2SigningOnly:
	default:
		return fmt.Errorf("protocol %v not supported", str)
	}
	*p = TokenProtocol(str)
	return nil
}
