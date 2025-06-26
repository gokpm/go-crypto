# go-crypto

Simple Go package for AES-256-GCM encryption and decryption with base64 encoding.

## Features

- **AES-256-GCM**: Authenticated encryption (confidentiality + integrity)
- **Base64 I/O**: Safe string handling for keys and encrypted data
- **Secure random nonces**: Each encryption uses a unique nonce
- **Error handling**: Proper validation and error reporting

## Installation

```bash
go get github.com/gokpm/go-crypto
```

## Usage

```go
import "github.com/gokpm/go-crypto"

// Encrypt data
key := "your-32-byte-base64-encoded-key"
data := []byte("Hello, World!")
encrypted, err := Encrypt(data, key)
if err != nil {
    log.Fatal(err)
}

// Decrypt data
decrypted, err := Decrypt(encrypted, key)
if err != nil {
    log.Fatal(err)
}
```

## Requirements

- Go 1.13+
- 32-byte (256-bit) base64-encoded key for AES-256

## Security Notes

- Uses cryptographically secure random nonce generation
- Nonce is automatically prepended to ciphertext
- GCM mode provides authentication - tampered data will fail decryption