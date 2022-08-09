package gpay

const (
	GoogleSenderId = "Google"

	EcV1            TokenProtocol = "ECv1"
	EcV2            TokenProtocol = "ECv2"
	EcV2SigningOnly TokenProtocol = "ECv2SigningOnly"

	Card          PaymentMethod = "CARD"
	TokenizedCard PaymentMethod = "TOKENIZED_CARD"
	PanOnly       AuthMethod    = "PAN_ONLY"
	Cryptogram3ds AuthMethod    = "CRYPTOGRAM_3DS"

	EnvMerchantId         = "GOOGLE_PAY_MERCHANT_ID"
	EnvMerchantPrivateKey = "GOOGLE_PAY_MERCHANT_PRIVATE_KEY"
	EnvRootSignedKetsFile = "GOOGLE_PAY_ROOT_SIGNED_KEYS_FILE"
)
