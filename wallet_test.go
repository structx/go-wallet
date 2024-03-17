package wallet_test

import (
	"testing"

	"github.com/trevatk/go-wallet"
)

func Test_Marshal(t *testing.T) {
	t.Run("to_file", func(t *testing.T) {
		w := wallet.New()
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
