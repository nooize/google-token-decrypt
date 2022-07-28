package gpay

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
)

type tokenDecrypt struct {
	merchantId         string
	merchantPrivateKey crypto.PrivateKey
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

	// Verify Intermediate Signing Key
	data := constructSignedData(
		GoogleSenderId, req.Protocol.String(), req.IntermediateKey.Key.Raw(),
	)
	if err := verifySignaturesWithRootKeys(req.IntermediateKey.Signatures, data); err != nil {
		return nil, err
	}

	// _validate_intermediate_signing_key
	if req.IntermediateKey.IsExpired() {
		return nil, errors.New("intermediate key is expired")
	}

	// Verify Message Signature
	data = constructSignedData(
		GoogleSenderId,
		d.merchantId,
		req.Protocol.String(),
		req.SignedMessage.Raw(),
	)
	publicKey, err := loadPublicKey(req.IntermediateKey.Key.Value)
	if err != nil {
		return nil, fmt.Errorf("unable load IntermediateKey : %s", err.Error())
	}
	if err := verifySignature(publicKey, data, req.Signature); err != nil {
		return nil, fmt.Errorf("invalid message signature: \n Exp: %s \n Error: %s", req.Signature.String(), err.Error())
	}

	return &GooglePayToken{
		Data: "",
	}, nil
}
