package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"github.com/gokpm/go-codec"
	"github.com/gokpm/go-sig"
)

var (
	ErrInvalidKeyLength = errors.New("decoded key must be 32 bytes (AES-256)")
	ErrShortCiphertext  = errors.New("ciphertext too short")
)

type Crypto interface {
	Encrypt(context.Context, []byte) (string, error)
	Decrypt(context.Context, string) ([]byte, error)
}

type aes256gcm struct {
	gcm       cipher.AEAD
	nonceSize int
}

func New(ctx context.Context, b64Key string) (Crypto, error) {
	log := sig.Start(ctx)
	defer log.End()
	key, err := codec.Decode(ctx, b64Key)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	if len(key) != 32 {
		log.Error(ErrInvalidKeyLength)
		return nil, ErrInvalidKeyLength
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return &aes256gcm{gcm: gcm, nonceSize: gcm.NonceSize()}, nil
}

func (a *aes256gcm) Encrypt(ctx context.Context, input []byte) (string, error) {
	log := sig.Start(ctx)
	defer log.End()
	nonce := make([]byte, a.nonceSize)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		log.Error(err)
		return "", err
	}
	ciphertext := a.gcm.Seal(nonce, nonce, input, nil)
	return codec.Encode(ctx, ciphertext), nil
}
func (a *aes256gcm) Decrypt(ctx context.Context, b64Input string) ([]byte, error) {
	log := sig.Start(ctx)
	defer log.End()
	data, err := codec.Decode(ctx, b64Input)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	if len(data) < a.nonceSize {
		log.Error(ErrShortCiphertext)
		return nil, ErrShortCiphertext
	}
	nonce, ciphertext := data[:a.nonceSize], data[a.nonceSize:]
	plaintext, err := a.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return plaintext, nil
}
