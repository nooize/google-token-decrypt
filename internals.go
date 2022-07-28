package gpay

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
)

var (
	defDecryptor ITokenDecryptor
)

func init() {
	defDecryptor = New("someRecipient")
	// loadRootSigningkeys()
}

func toBase64(v []byte) string {
	return base64.StdEncoding.EncodeToString(v)
}

func hmacSha256(key []byte, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func constructSignedData(args ...string) []byte {
	res := make([]byte, 0)
	for _, v := range args {
		vBytes := []byte(v)
		lBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(lBytes, uint32(len(vBytes)))
		res = append(res, lBytes...)
		res = append(res, vBytes...)
	}
	return res
}

func loadPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA public key : %s", toBase64(data))
	}

	publicKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not a ECDSA public key : %s", toBase64(data))
	}
	return publicKey, nil
}

func verifySignature(key *ecdsa.PublicKey, data []byte, signature []byte) error {
	s := struct{ R, S *big.Int }{big.NewInt(0), big.NewInt(0)}
	if _, err := asn1.Unmarshal(signature, s); err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	if !ecdsa.Verify(key, hash[:], s.R, s.S) {
		return fmt.Errorf("invalid signature: \n Exp: %s", toBase64(data))
	}
	return nil
}
