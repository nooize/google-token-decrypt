package gpay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
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

type PaymentMethod string

func (m *PaymentMethod) String() string {
	return string(*m)
}

func (m *PaymentMethod) UnmarshalJSON(bytes []byte) error {
	str, _ := strconv.Unquote(string(bytes))
	switch PaymentMethod(str) {
	case Card:
	case TokenizedCard:
	default:
		return fmt.Errorf("payment method %v not supported", str)
	}
	*m = PaymentMethod(str)
	return nil
}

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

type JsonBase64 []byte

func (v JsonBase64) String() string {
	return toBase64(v)
}

func (v *JsonBase64) UnmarshalJSON(bytes []byte) error {
	str, err := unmarshalString(bytes)
	if err != nil {
		return err
	}
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	*v = data
	return nil
}

type JsonTimestamp struct {
	time.Time
}

func (v *JsonTimestamp) UnmarshalJSON(bytes []byte) error {
	str := ""
	if err := json.Unmarshal(bytes, &str); err != nil {
		return err
	}
	ts, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		return fmt.Errorf("%s is not unix time stamp", str)
	}
	if err != nil {
		return err
	}
	lt := time.Unix(ts/1000, 0)
	*v = JsonTimestamp{time.Date(lt.Year(), lt.Month(), lt.Day(), lt.Hour(), lt.Minute(), lt.Second(), 00, time.UTC)}
	return nil
}
