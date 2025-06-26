package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"github.com/gokpm/go-codec"
)

type Crypto interface {
	Encrypt([]byte) (string, error)
	Decrypt(string) ([]byte, error)
}

type aes256gcm struct {
	gcm       cipher.AEAD
	nonceSize int
}

func New(b64Key string) (Crypto, error) {
	key, err := codec.Decode(b64Key)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("decoded key must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &aes256gcm{gcm: gcm, nonceSize: gcm.NonceSize()}, nil
}

func (a *aes256gcm) Encrypt(input []byte) (string, error) {
	nonce := make([]byte, a.nonceSize)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}
	ciphertext := a.gcm.Seal(nonce, nonce, input, nil)
	return codec.Encode(ciphertext), nil
}
func (a *aes256gcm) Decrypt(b64Input string) ([]byte, error) {
	data, err := codec.Decode(b64Input)
	if err != nil {
		return nil, err
	}
	if len(data) < a.nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:a.nonceSize], data[a.nonceSize:]
	plaintext, err := a.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
