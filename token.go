package gpay

type GooglePayToken struct {
	MessageId           string `json:"messageId"`
	MessageExpiration   string `json:"messageExpiration"`
	PaymenMethod        string `json:"paymentMethod"`
	GatewayMerchantId   string `json:"gatewayMerchantId,omitempty"`
	PaymenMethodDetails struct {
		AuthMethod      AuthMethod `json:"authMethod"`
		Pan             string     `json:"pan"`
		ExpirationMonth int        `json:"expirationMonth"`
		ExpirationYear  int        `json:"expirationYear"`
		Cryptogram      string     `json:"cryptogram,omitempty"`
		EciIndicator    string     `json:"eciIndicator,omitempty"`
	} `json:"paymentMethodDetails"`
}
