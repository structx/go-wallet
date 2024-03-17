package examples

import (
	"testing"

	"github.com/trevatk/go-wallet"
)

func Test_GenerateWallet(t *testing.T) {
	w := wallet.NewWallet()

	addr, err := w.Address()
	if err != nil {
		t.Fatalf("failed to generate wallet address %v", err)
	}

	t.Logf("wallet public key %s", addr)
}
