// Package wallet functionality
package wallet

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/suites"
	"golang.org/x/crypto/salsa20"
)

var (
	key   = [32]byte{}
	nonce = [8]byte{}
)

// Wallet ...
type Wallet struct {
	p    kyber.Scalar
	P    kyber.Point
	Addr string
	s    suites.Suite
}

type exportWallet struct {
	PublicKey  []byte `json:"public_key"`
	PrivateKey []byte `json:"private_key"`
	Address    string `json:"address"`
}

// New return new wallet
func New() *Wallet {

	suite := edwards25519.NewBlakeSHA256Ed25519()
	rand := suite.RandomStream()

	x := suite.Scalar().Pick(rand) // private key
	X := suite.Point().Mul(x, nil) // public key

	return &Wallet{
		P:    X,
		p:    x,
		s:    suite,
		Addr: "",
	}
}

// Address from wallet public key
func (w *Wallet) Address() (string, error) {

	if w.Addr != "" {
		return w.Addr, nil
	}

	publicbytes, err := w.P.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key %v", err)
	}

	out := make([]byte, len(publicbytes))
	salsa20.XORKeyStream(out, publicbytes, nonce[:], &key)

	return hex.EncodeToString(out), nil
}

// MarshalToFile export wallet to file
func (w *Wallet) MarshalToFile(path string) error {

	// transform wallet to export wallet
	ew, err := createExportWallet(w)
	if err != nil {
		return fmt.Errorf("unable to create export wallet %v", err)
	}

	// convert export wallet to bytes
	walletbytes, err := json.Marshal(ew)
	if err != nil {
		return fmt.Errorf("failed to marshal bytes %v", err)
	}

	// write bytes to file
	path = filepath.Clean(path)
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create wallet file %v", err)
	}
	defer func() { _ = f.Close() }()

	_, err = f.Write(walletbytes)
	if err != nil {
		return fmt.Errorf("failed to write wallet to file %v", err)
	}

	return nil
}

// UnmarshalFromFile read wallet from file
func UnmarshalFromFile(path string) (*Wallet, error) {

	path = filepath.Clean(path)
	filebytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %v", err)
	}

	var export exportWallet
	err = json.Unmarshal(filebytes, &export)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal bytes %v", err)
	}

	var w Wallet
	w.s = edwards25519.NewBlakeSHA256Ed25519()

	w.P = w.s.Point()
	w.p = w.s.Scalar()

	err = w.P.UnmarshalBinary(export.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key %v", err)
	}

	err = w.p.UnmarshalBinary(export.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key %v", err)
	}

	return &w, nil
}

func createExportWallet(w *Wallet) (*exportWallet, error) {

	publicbytes, err := w.P.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key %v", err)
	}

	privatebytes, err := w.p.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key %v", err)
	}

	addr, err := w.Address()
	if err != nil {
		return nil, fmt.Errorf("failed to read wallet address %v", err)
	}

	return &exportWallet{
		PublicKey:  publicbytes,
		PrivateKey: privatebytes,
		Address:    addr,
	}, nil
}
