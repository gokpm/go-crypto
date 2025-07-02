package crypto_test

import (
	"testing"

	"github.com/gokpm/go-crypto"
)

const (
	key1 = "6qeMd42Hu4ADafAmlodZAZllQAz1Hi9g5Cm5262ZyPI="
	key2 = "/Kx//iAQKjwh5RPrEqdUR1hGwv8UYkOG6ntyG9ichpE="
	key3 = "key"
)

func TestEncryptDecrypt(t *testing.T) {
	cr, err := crypto.New(key1)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := "apple"
	ciphertext, err := cr.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := cr.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != plaintext {
		t.Fatal("decrypted != plaintext")
	}
}

func TestEncryptDecryptDifferentKeys(t *testing.T) {
	cr1, err := crypto.New(key1)
	if err != nil {
		t.Fatal(err)
	}
	cr2, err := crypto.New(key2)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := "apple"
	ciphertext, err := cr1.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	_, err = cr2.Decrypt(ciphertext)
	if err == nil {
		t.Fatal("expected error")
	}
}
