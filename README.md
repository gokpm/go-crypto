# go-crypto

A Go package providing AES-256-GCM encryption/decryption with base64 encoding and structured logging.

## Installation

```bash
go get github.com/gokpm/go-crypto
```

## Usage

```go
import (
    "context"
    "github.com/gokpm/go-crypto"
)

ctx := context.Background()

// Create crypto instance with base64-encoded 32-byte key
b64Key := "your-base64-encoded-32-byte-key"
c, err := crypto.New(ctx, b64Key)
if err != nil {
    panic(err)
}

// Encrypt data
data := []byte("secret message")
encrypted, err := c.Encrypt(ctx, data)
if err != nil {
    panic(err)
}

// Decrypt data
decrypted, err := c.Decrypt(ctx, encrypted)
if err != nil {
    panic(err)
}
```

## Interface

```go
type Crypto interface {
    Encrypt(context.Context, []byte) (string, error)
    Decrypt(context.Context, string) ([]byte, error)
}
```

## Features

- AES-256-GCM authenticated encryption
- Automatic nonce generation for each encryption
- Base64 encoding of encrypted output
- Structured logging via [go-sig](https://github.com/gokpm/go-sig)
- Input validation and error handling

## Errors

- `ErrInvalidKeyLength` - Key must be exactly 32 bytes (AES-256)
- `ErrShortCiphertext` - Ciphertext too short to contain valid nonce

## License

MIT