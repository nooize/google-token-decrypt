package gpay

import "crypto/ecdsa"

const (
	GoogleSenderId = "Google"
)

func New(recipient string, key *ecdsa.PrivateKey) ITokenDecryptor {
	return &tokenDecrypt{merchantId: recipient, merchantPrivateKey: key}
}

func DecryptToken(tokenData []byte) (*GooglePayToken, error) {
	return defDecryptor.Decrypt(tokenData)
}

type ITokenDecryptor interface {
	Decrypt([]byte) (*GooglePayToken, error)
}
