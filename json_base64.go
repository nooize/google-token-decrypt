package gpay

import (
	"encoding/base64"
	"strconv"
)

type JsonBase64 []byte

func (v JsonBase64) String() string {
	return toBase64(v)
}

func (v *JsonBase64) UnmarshalJSON(bytes []byte) error {
	str, _ := strconv.Unquote(string(bytes))
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	*v = data
	return nil
}
