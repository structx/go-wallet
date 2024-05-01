package wallet_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/structx/go-wallet"
)

func Test_NewWallet(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		assert := assert.New(t)
		w := wallet.NewWallet()
		assert.NotNil(w)
	})
	t.Run("with_version", func(t *testing.T) {
		assert := assert.New(t)
		w := wallet.NewWalletWithVersion(wallet.MinVersion)
		assert.NotNil(w)
	})
}

func Test_Signature(t *testing.T) {
	t.Run("verified", func(t *testing.T) {
		assert := assert.New(t)
		w := wallet.NewWallet()
		p := []byte("hello world")

		sig, err := w.Signature(p)
		assert.NoError(err)

		err = w.VerifySignature(p, sig)
		assert.NoError(err)
	})
	t.Run("mismatch", func(t *testing.T) {
		assert := assert.New(t)
		w := wallet.NewWallet()
		w2 := wallet.NewWallet()
		p := []byte("hello world")

		sig, err := w.Signature(p)
		assert.NoError(err)

		err = w2.VerifySignature(p, sig)
		assert.Equal(wallet.ErrSignatureMisMatch, err)
	})
}

func Test_Marshal(t *testing.T) {
	t.Run("to_file", func(t *testing.T) {
		w := wallet.NewWallet()
		err := w.MarshalToFile("./testfiles/w1.json")
		if err != nil {
			t.Fatalf("failed to marshal wallet to file %v", err)
		}
	})
}

func Test_UnmarshalFromFile(t *testing.T) {
	t.Run("from_file", func(t *testing.T) {
		w, err := wallet.UnmarshalFromFile("./testfiles/w1.json")
		if err != nil {
			t.Fatalf("failed to unmarshal wallet %v", err)
		}

		addr, err := w.Address()
		if err != nil {
			t.Fatalf("failed to generate wallet address %v", err)
		}

		t.Logf("wallet address %s", addr)
	})
}
