// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/coming-chat/coming-go-v2/helpers"
	log "github.com/sirupsen/logrus"
)

// randBytes returns a sequence of random bytes from the CSPRNG
func RandBytes(data []byte) {
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
}

// randUint32 returns a random 32bit uint from the CSPRNG
func RandUint32() uint32 {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint32(b)
}

// appendMAC returns the given message with a HMAC-SHA256 MAC appended
func AppendMAC(key, b []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(b)
	return m.Sum(b)
}

// ComputeTruncatedMAC computes a HMAC-SHA256 MAC and returns its prefix of a given size.
func ComputeTruncatedMAC(msg, key []byte, size int) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)[:size]
}

// verifyMAC verifies a HMAC-SHA256 MAC on a message
func VerifyMAC(key, b, mac []byte) bool {
	actualMAC := ComputeTruncatedMAC(b, key, len(mac))
	return hmac.Equal(actualMAC, mac)
}

// telToToken calculates a truncated SHA1 hash of a phone number, to be used for contact discovery
func telToToken(tel string) string {
	s := sha1.Sum([]byte(tel))
	return helpers.Base64EncWithoutPadding(s[:10])
}

// aesEncrypt encrypts the given plaintext under the given key in AES-CBC mode
func AesEncrypt(key, plaintext []byte) ([]byte, error) {
	iv := make([]byte, 16)
	RandBytes(iv)
	ciphertext, err := AesEncryptWithIv(key, iv, plaintext)
	if err != nil {
		return nil, err
	}
	return append(iv, ciphertext...), nil
}

func AesEncryptWithIv(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(plaintext)%aes.BlockSize
	plaintext = append(plaintext, bytes.Repeat([]byte{byte(pad)}, pad)...)
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// aesDecrypt decrypts the given ciphertext under the given key in AES-CBC mode
func AesDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		length := len(ciphertext) % aes.BlockSize
		log.Debugln("[textsecure] aesDecrypt ciphertext not multiple of AES blocksize", length)
		return nil, errors.New("ciphertext not multiple of AES blocksize")
	}

	iv := ciphertext[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	pad := ciphertext[len(ciphertext)-1]
	if pad > aes.BlockSize {
		return nil, fmt.Errorf("pad value (%d) larger than AES blocksize (%d)", pad, aes.BlockSize)
	}
	return ciphertext[aes.BlockSize : len(ciphertext)-int(pad)], nil
}

func aesCtrNoPaddingDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		length := len(ciphertext) % aes.BlockSize
		log.Debugln("[textsecure] aesDecrypt ciphertext not multiple of AES blocksize", length)
		return nil, errors.New("ciphertext not multiple of AES blocksize")
	}

	iv := ciphertext[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)
	// s := string(ciphertext[:])

	return ciphertext, nil

	// return ciphertext[aes.BlockSize : len(ciphertext)-int(pad)], nil
}
