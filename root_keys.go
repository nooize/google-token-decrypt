package gpay

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

const testRootkeys = "[{\n    \"keyValue\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==\",\n    \"keyExpiration\": \"32506264800000\",\n    \"protocolVersion\": \"ECv2\"\n}]"

const (
	TestRootKeysUrl       = "https://payments.developers.google.com/paymentmethodtoken/keys.json"
	ProductionRootKeysUrl = "https://payments.developers.google.com/paymentmethodtoken/keys.json"
)

var (
	rootSigningKeys   = make([]*rootSigningKey, 0)
	rootSigningKeysMu = sync.RWMutex{}
)

type signingKeyOptions struct {
	Protocol   TokenProtocol `json:"protocolVersion"`
	Expiration string        `json:"keyExpiration"`
}

type rootSigningKey struct {
	signingKeyOptions
	Production bool
	Key        *ecdsa.PublicKey
}

func verifySignaturesWithRootKeys(signatures []JsonBase64, data []byte) error {
	for _, publicKey := range rootSigningKeys {
		for _, signature := range signatures {
			if err := verifySignature(publicKey.Key, data, signature); err == nil {
				return nil
			}
		}
	}
	return fmt.Errorf("invalid signature for intermediate signing key")
}

func fetchRootSigningkeys() {
	keys := make([]*rootSigningKey, 0)
	if list, err := fetchKeysFromUrl(ProductionRootKeysUrl, true); err != nil {
		// TODO log error
	} else {
		keys = append(keys, list...)
	}
	if list, err := fetchKeysFromUrl(TestRootKeysUrl, true); err != nil {
		// TODO log error
	} else {
		keys = append(keys, list...)
	}
	rootSigningKeysMu.Lock()
	rootSigningKeys = keys
	rootSigningKeysMu.Unlock()
}

func fetchKeysFromUrl(url string, isProduction bool) ([]*rootSigningKey, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out := make([]*rootSigningKey, 0)
	if err = json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	for _, v := range out {
		v.Production = isProduction
	}
	return out, nil
}

func parseRootSigningkeys() {
	keys := make([]*rootSigningKey, 0)
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
			keys = append(keys, key)
		}
	}
	rootSigningKeysMu.Lock()
	rootSigningKeys = keys
	rootSigningKeysMu.Unlock()
}
