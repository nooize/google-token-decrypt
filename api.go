package gpay

const (
	GoogleSenderId = "Google"
)

func New(recipient string) ITokenDecryptor {
	return &tokenDecrypt{merchantId: recipient}
}

func DecryptToken(tokenData []byte) (*GooglePayToken, error) {
	return defDecryptor.Decrypt(tokenData)
}

type ITokenDecryptor interface {
	Decrypt([]byte) (*GooglePayToken, error)
}
