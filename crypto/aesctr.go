package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

func AESCtrEncrypt(key, nonce, input []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesctr := cipher.NewCTR(block, nonce)
	dst := make([]byte, len(input))
	aesctr.XORKeyStream(dst, input)
	return dst, nil
}
