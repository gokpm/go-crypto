package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

func Encrypt(input []byte, b64Key string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return "", err
	}
	if len(key) != 32 {
		return "", errors.New("decoded key must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, input, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(b64Input string, b64Key string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("decoded key must be 32 bytes (AES-256)")
	}
	data, err := base64.StdEncoding.DecodeString(b64Input)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("cipherText too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
