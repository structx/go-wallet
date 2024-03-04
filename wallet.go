// Package wallet functionality
package wallet

import (
	"encoding/hex"
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"golang.org/x/crypto/salsa20"
)

var (
	key   = [32]byte{}
	nonce = [8]byte{}
)

// Wallet ...
type Wallet struct {
	p kyber.Scalar
	P kyber.Point
}

// NewWallet return new wallet
func NewWallet() *Wallet {

	suite := edwards25519.NewBlakeSHA256Ed25519()
	rand := suite.RandomStream()

	x := suite.Scalar().Pick(rand) // private key
	X := suite.Point().Mul(x, nil) // public key

	return &Wallet{
		P: X,
		p: x,
	}
}

// Address from wallet public key
func (w *Wallet) Address() (string, error) {

	publicbytes, err := w.P.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key %v", err)
	}

	out := make([]byte, len(publicbytes))
	salsa20.XORKeyStream(out, publicbytes, nonce[:], &key)

	return hex.EncodeToString(out), nil
}
