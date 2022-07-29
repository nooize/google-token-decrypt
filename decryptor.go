package gpay

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"encoding/json"
	"errors"
)

type tokenDecrypt struct {
	merchantId         string
	merchantPrivateKey *ecdsa.PrivateKey
}

func (d *tokenDecrypt) Decrypt(input []byte) (*GooglePayToken, error) {
	req := new(encryptedToken)
	if err := json.Unmarshal(input, req); err != nil {
		return nil, err
	}

	/*
		if (!payload.has(PaymentMethodTokenConstants.JSON_ENCRYPTED_MESSAGE_KEY)
		|| !payload.has(PaymentMethodTokenConstants.JSON_TAG_KEY)
		|| !payload.has(PaymentMethodTokenConstants.JSON_EPHEMERAL_PUBLIC_KEY)
		|| payload.size() != 3) {
	*/
	switch {
	case len(req.Signature) == 0:
		return nil, errors.New("signature is empty")
	case len(req.IntermediateKey.Key.Value) == 0:
		return nil, errors.New("intermediate signed key value is empty")
	case len(req.IntermediateKey.Signatures) == 0:
		return nil, errors.New("intermediate key signatures is empty")
	}

	if err := req.verifyIntermediateSigningKey(); err != nil {
		return nil, err
	}

	// _validate_intermediate_signing_key
	if req.IntermediateKey.IsExpired() {
		return nil, errors.New("intermediate key is expired")
	}

	if err := req.verifyMessageSignature(d.merchantId); err != nil {
		return nil, err
	}

	deriveKey, err := d.getDeriveKey(req.SignedMessage.EphemeralPublicKey)
	if err != nil {
		return nil, err
	}
	symmetricKey := deriveKey[:32]

	messageMac := hmacSha256(deriveKey[32:], []byte(req.SignedMessage.Raw()))
	if hmac.Equal(req.SignedMessage.Tag, messageMac) {
		return nil, errors.New("encrypted message MAC is not valid MAC Tag ")
	}

	cip, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(req.SignedMessage.EncryptedMessage))
	ctr := cipher.NewCTR(cip, make([]byte, aes.BlockSize))
	//out := make([]byte, 0)
	ctr.XORKeyStream(out, req.SignedMessage.EncryptedMessage)

	return &GooglePayToken{
		Data: string(out),
	}, nil
}

func (d *tokenDecrypt) getDeriveKey(ephemeralBytes []byte) ([]byte, error) {
	public, err := unmarshalPublicKey(ephemeralBytes)
	if err != nil {
		return nil, err
	}
	x, _ := public.Curve.ScalarMult(public.X, public.Y, d.merchantPrivateKey.D.Bytes())
	if x == nil {
		return nil, errors.New("scalar multiplication resulted in infinity")
	}

	demKey, err := computeHKDF(
		append(ephemeralBytes, x.Bytes()...), // key
		make([]byte, 32),                     // empty salt
		[]byte(GoogleSenderId),
		64)
	if err != nil {
		return nil, err
	}
	return demKey, nil
}
