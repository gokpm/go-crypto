package crypto_test

import (
	"context"
	"testing"

	"github.com/gokpm/go-crypto"
)

const (
	key1 = "6qeMd42Hu4ADafAmlodZAZllQAz1Hi9g5Cm5262ZyPI="
	key2 = "/Kx//iAQKjwh5RPrEqdUR1hGwv8UYkOG6ntyG9ichpE="
	key3 = "key"
)

func TestNew(t *testing.T) {
	ctx := context.TODO()
	cr1, err := crypto.New(ctx, key1)
	if err != nil {
		t.Fatal(err)
	}
	cr2, err := crypto.New(ctx, key2)
	if err != nil {
		t.Fatal(err)
	}
	if cr1.Key() != key1 {
		t.Fatal("key mismatch")
	}
	if cr2.Key() != key2 {
		t.Fatal("key mismatch")
	}
	_, err = crypto.New(ctx, key3)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	ctx := context.TODO()
	cr, err := crypto.New(ctx, key1)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := "apple"
	ciphertext, err := cr.Encrypt(ctx, []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := cr.Decrypt(ctx, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != plaintext {
		t.Fatal("decrypted != eplaintextrror")
	}
}

func TestEncryptDecryptDifferentKeys(t *testing.T) {
	ctx := context.TODO()
	cr1, err := crypto.New(ctx, key1)
	if err != nil {
		t.Fatal(err)
	}
	cr2, err := crypto.New(ctx, key2)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := "apple"
	ciphertext, err := cr1.Encrypt(ctx, []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	_, err = cr2.Decrypt(ctx, ciphertext)
	if err == nil {
		t.Fatal("expected error")
	}
}
