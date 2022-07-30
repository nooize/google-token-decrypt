package gpay

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

type encryptedToken struct {
	Protocol        TokenProtocol   `json:"protocolVersion"`
	Signature       JsonBase64      `json:"signature"`
	IntermediateKey intermediateKey `json:"intermediateSigningKey"`
	SignedMessage   signedMessage   `json:"signedMessage"`
}

func (v *encryptedToken) verifyIntermediateSigningKey() error {
	data := constructSignedData(
		GoogleSenderId,
		string(v.Protocol),
		v.IntermediateKey.Key.Raw(),
	)
	return verifySignaturesWithRootKeys(v.IntermediateKey.Signatures, data)
}

func (v *encryptedToken) verifyMessageSignature(recipient string) error {
	publicKey, err := loadPublicKey(v.IntermediateKey.Key.Value)
	if err != nil {
		return err
	}
	data := constructSignedData(
		GoogleSenderId,
		recipient,
		string(v.Protocol),
		v.SignedMessage.Raw(),
	)

	if err := verifySignature(publicKey, data, v.Signature); err != nil {
		return fmt.Errorf("invalid message signature: \n Exp: %s \n Error: %s", toBase64(v.Signature), err.Error())
	}

	return nil

}

type intermediateKey struct {
	Key        signedKey    `json:"signedKey"`
	Signatures []JsonBase64 `json:"signatures"`
}

func (v intermediateKey) IsExpired() bool {
	i, err := strconv.Atoi(v.Key.Expiration)
	if err != nil {
		return true
	}
	// TODO localize time
	if int64(i) < time.Now().Unix() {
		return true
	}
	return false
}

type baseSignedKey struct {
	Value      JsonBase64 `json:"keyValue"`
	Expiration string     `json:"keyExpiration"`
}

type signedKey struct {
	baseSignedKey
	raw string
}

func (v *signedKey) Raw() string {
	return v.raw
}

func (v *signedKey) UnmarshalJSON(bytes []byte) (err error) {
	v.raw, err = strconv.Unquote(string(bytes))
	if err != nil {
		return err
	}
	k := baseSignedKey{}
	if err = json.Unmarshal([]byte(v.raw), &k); err != nil {
		return err
	}
	v.baseSignedKey = k
	return nil
}

type baseSignedMessage struct {
	EncryptedMessage   JsonBase64 `json:"encryptedMessage"`
	EphemeralPublicKey JsonBase64 `json:"ephemeralPublicKey"`
	Tag                JsonBase64 `json:"tag"`
}

type signedMessage struct {
	baseSignedMessage
	raw string
}

func (v *signedMessage) Raw() string {
	return v.raw
}

func (v *signedMessage) UnmarshalJSON(bytes []byte) (err error) {
	v.raw, err = strconv.Unquote(string(bytes))
	if err != nil {
		return err
	}
	t := baseSignedMessage{}
	if err = json.Unmarshal([]byte(v.raw), &t); err != nil {
		return err
	}
	v.baseSignedMessage = t
	return nil
}
