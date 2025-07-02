package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"github.com/gokpm/go-codec"
)

var (
	// ErrInvalidKeyLength is returned when the decoded key is not 32 bytes
	ErrInvalidKeyLength = errors.New("decoded key must be 32 bytes (AES-256)")
	// ErrShortCiphertext is returned when the ciphertext is too short to contain a valid nonce
	ErrShortCiphertext = errors.New("ciphertext too short")
)

// Crypto defines the interface for encryption/decryption operations
type Crypto interface {
	Encrypt([]byte) (string, error)
	Decrypt(string) ([]byte, error)
}

// aes256gcm implements the Crypto interface using AES-256-GCM
type aes256gcm struct {
	gcm       cipher.AEAD // GCM cipher mode
	nonceSize int         // Size of the nonce in bytes
}

// New creates a new Crypto instance with the provided base64-encoded key
func New(b64Key string) (Crypto, error) {
	// Decode the base64 key
	key, err := codec.Decode(b64Key)
	if err != nil {
		return nil, err
	}
	// Validate key length for AES-256
	if len(key) != 32 {
		return nil, ErrInvalidKeyLength
	}
	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &aes256gcm{gcm: gcm, nonceSize: gcm.NonceSize()}, nil
}

// Encrypt encrypts the input data and returns base64-encoded ciphertext
func (a *aes256gcm) Encrypt(input []byte) (string, error) {
	// Generate random nonce
	nonce := make([]byte, a.nonceSize)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}
	// Encrypt data (nonce is prepended to ciphertext)
	ciphertext := a.gcm.Seal(nonce, nonce, input, nil)
	// Generate random nonce
	return codec.Encode(ciphertext), nil
}

// Decrypt decrypts the base64-encoded input and returns plaintext
func (a *aes256gcm) Decrypt(b64Input string) ([]byte, error) {
	// Decode base64 input
	data, err := codec.Decode(b64Input)
	if err != nil {
		return nil, err
	}
	// Validate minimum length (must contain nonce)
	if len(data) < a.nonceSize {
		return nil, ErrShortCiphertext
	}
	// Split nonce and ciphertext
	nonce, ciphertext := data[:a.nonceSize], data[a.nonceSize:]
	// Decrypt and authenticate
	plaintext, err := a.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
