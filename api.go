package gpay

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strings"
)

const (
	GoogleSenderId        = "Google"
	EnvMerchantId         = "GOOGLE_PAY_MERCHANT_ID"
	EnvMerchantPrivateKey = "GOOGLE_PAY_MERCHANT_PRIVATE_KEY"
)

type ITokenDecryptor interface {
	Decrypt([]byte) (*GooglePayToken, error)
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
