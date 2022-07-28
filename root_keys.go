package gpay

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
)

const testRootkeys = "[{\n    \"keyValue\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==\",\n    \"keyExpiration\": \"32506264800000\",\n    \"protocolVersion\": \"ECv2\"\n}]"

var (
	rootSigningkeys = make([]*rootSigningKey, 0)
)

type signingKeyOptions struct {
	Protocol   TokenProtocol `json:"protocolVersion"`
	Expiration string        `json:"keyExpiration"`
}

type rootSigningKey struct {
	signingKeyOptions
	Key *ecdsa.PublicKey
}

func verifySignaturesWithRootKeys(signatures []JsonBase64, data []byte) error {
	for _, publicKey := range rootSigningkeys {
		for _, signature := range signatures {
			if err := verifySignature(publicKey.Key, data, signature); err == nil {
				return nil
			}
		}
	}
	return fmt.Errorf("invalid signature for intermediate signing key")
}

func loadRootSigningkeys() {
	rootSigningkeys = make([]*rootSigningKey, 0)
	list := make([]struct {
		signingKeyOptions
		Value JsonBase64 `json:"keyValue"`
	}, 0)
	if err := json.Unmarshal([]byte(testRootkeys), &list); err != nil {
		return
	}
	for _, v := range list {
		key := &rootSigningKey{signingKeyOptions: v.signingKeyOptions}
		if publicKey, err := loadPublicKey(v.Value); err == nil {
			key.Key = publicKey
			rootSigningkeys = append(rootSigningkeys, key)
		}
	}
}
