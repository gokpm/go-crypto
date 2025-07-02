# go-crypto

A Go package providing AES-256-GCM encryption/decryption with base64 encoding.

## Installation

```bash
go get github.com/gokpm/go-crypto
```

## Usage

```go
import (
    "log"
    "github.com/gokpm/go-crypto"
)

// Create crypto instance with base64-encoded 32-byte key
b64Key := "your-base64-encoded-32-byte-key"
c, err := crypto.New(b64Key)
if err != nil {
    log.Fatalln(err)
}

// Encrypt data
data := []byte("secret message")
encrypted, err := c.Encrypt(data)
if err != nil {
    log.Fatalln(err)
}

// Decrypt data
decrypted, err := c.Decrypt(encrypted)
if err != nil {
    log.Fatalln(err)
}
```

## Interface

```go
type Crypto interface {
    Encrypt([]byte) (string, error)
    Decrypt(string) ([]byte, error)
}
```

## Features

- AES-256-GCM authenticated encryption
- Automatic nonce generation for each encryption
- Base64 encoding of encrypted output
- Input validation and error handling

## Errors

- `ErrInvalidKeyLength` - Key must be exactly 32 bytes (AES-256)
- `ErrShortCiphertext` - Ciphertext too short to contain valid nonce

## License

MIT