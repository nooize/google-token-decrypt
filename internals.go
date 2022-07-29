package gpay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
	"os"
)

const (
	// Minimum tag size in bytes. This provides minimum 80-bit security strength.
	minTagSizeInBytes = uint32(10)
	tagDigestSize     = uint32(32)
)

var (
	defDecryptor ITokenDecryptor
)

func init() {
	if raw := os.Getenv("GOOGLE_PAY_MERCHANT_PRIVATE_KEY"); len(raw) > 0 {
		bytes, err := base64.StdEncoding.DecodeString(raw)
		key, err := loadPrivateKey(bytes)
		if err != nil {
			return
		}
		defDecryptor = New("someRecipient", key)
	}
	loadRootSigningkeys()
}

func uintToBytes(v uint32) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, v)
	return out
}

func toBase64(v []byte) string {
	return base64.StdEncoding.EncodeToString(v)
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

func hmacSha256(key []byte, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func loadPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, errors.New("failed to parse ECDSA private key")
	}
	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not a ECDSA private key")
	}
	return privateKey, nil
}

func unmarshalPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), data)
	if x == nil {
		// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_ftn1
		// PKCS#11 v2.20 specified that the CKA_EC_POINT was to be store in a DER-encoded
		// OCTET STRING.
		var point asn1.RawValue
		asn1.Unmarshal(data, &point)
		if len(point.Bytes) > 0 {
			x, y = elliptic.Unmarshal(elliptic.P256(), point.Bytes)
		}
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func loadPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, errors.New("failed to parse ECDSA public key")
	}

	publicKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Not a ECDSA public key")
	}

	//x, y := elliptic.Unmarshal(curve, data)
	//cert := new(ecdsa.PublicKey)
	//cert.Curve = curve
	//cert.X = x
	//cert.Y = y

	return publicKey, nil
	//ecdsa.Verify(nil, key, nil, nil)
	//return cast(EllipticCurvePublicKey, load_der_public_key(derdata, default_backend()))
}

func verifySignature(key *ecdsa.PublicKey, data []byte, signature []byte) error {
	sign := struct {
		R *big.Int
		S *big.Int
	}{big.NewInt(0), big.NewInt(0)}
	if _, err := asn1.Unmarshal(signature, &sign); err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	if !ecdsa.Verify(key, hash[:], sign.R, sign.S) {
		return fmt.Errorf("invalid signature: \n Exp: %s", toBase64(data))
	}
	return nil
}

func computeHKDF(key []byte, salt []byte, info []byte, tagSize uint32) ([]byte, error) {

	if tagSize > 255*tagDigestSize {
		return nil, fmt.Errorf("tag size too big")
	}
	if tagSize < minTagSizeInBytes {
		return nil, fmt.Errorf("tag size too small")
	}

	if len(salt) == 0 {
		salt = make([]byte, sha256.New().Size())
	}

	result := make([]byte, tagSize)
	kdf := hkdf.New(sha256.New, key, salt, info)
	n, err := io.ReadFull(kdf, result)
	if n != len(result) || err != nil {
		return nil, fmt.Errorf("compute of hkdf failed")
	}

	return result, nil
}
