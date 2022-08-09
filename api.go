package gpay

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

type ITokenDecryptor interface {
	Decrypt([]byte) (*GooglePayToken, error)
	MerchantId() string
}

func New(recipient string, key *ecdsa.PrivateKey) (ITokenDecryptor, error) {
	if recipient = strings.TrimSpace(recipient); len(recipient) == 0 {
		return nil, errors.New("recipient is empty")
	}
	if key == nil {
		return nil, errors.New("private key is nil")
	}
	return &tokenDecrypt{merchantId: recipient, merchantPrivateKey: key}, nil
}

func Decrypt(data []byte) (*GooglePayToken, error) {
	if defDecryptor == nil {
		return nil, fmt.Errorf("default token decryptor not defined")
	}
	return defDecryptor.Decrypt(data)
}

func ParseMerchantPrivateKey(str string) (*ecdsa.PrivateKey, error) {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return loadPrivateKey(data)
}

func UnmarshalMerchantPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	return loadPrivateKey(data)
}
