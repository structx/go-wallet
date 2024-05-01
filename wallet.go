// Package wallet functionality
package wallet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/util/random"

	"golang.org/x/crypto/salsa20"
)

var (
	// MinVersion minimum supported version of wallet
	MinVersion = 1

	key   = [32]byte{}
	nonce = [8]byte{}
)

type suite interface {
	kyber.Group
	kyber.Encoding
	kyber.XOFFactory
}

// Wallet ...
type Wallet interface {

	// Address generate wallet address
	Address() (string, error)
	// Signature
	Signature(payload []byte) ([]byte, error)
	// VerifySignature
	VerifySignature(payload, signature []byte) error

	// MarshalToFile
	MarshalToFile(path string) error

	// GetPublicKey getter public key
	GetPublicKey() ([]byte, error)
	// GetVersion getter versionn
	GetVersion() string
}

type sigWallet struct {
	C kyber.Scalar // challenge
	R kyber.Scalar // response
}

// BasicWallet simple implementation of wallet
type BasicWallet struct {
	x       kyber.Scalar
	y       kyber.Point
	addr    string
	suite   suite
	version string
}

// interface compliance
var _ Wallet = (*BasicWallet)(nil)

type exportWallet struct {
	PublicKey  []byte `json:"public_key"`
	PrivateKey []byte `json:"private_key"`
	Address    string `json:"address"`
	Version    string `json:"version"`
}

// NewWallet return new wallet
func NewWallet() *BasicWallet {

	suite := edwards25519.NewBlakeSHA256Ed25519()
	rand := suite.RandomStream()

	x := suite.Scalar().Pick(rand) // private key
	y := suite.Point().Mul(x, nil) // public key

	return &BasicWallet{
		x:       x,
		y:       y,
		addr:    "",
		suite:   suite,
		version: fmt.Sprintf("%d", MinVersion),
	}
}

// NewWalletWithVersion return new wallet with version
func NewWalletWithVersion(version int) *BasicWallet {

	suite := edwards25519.NewBlakeSHA256Ed25519()
	rand := suite.RandomStream()

	x := suite.Scalar().Pick(rand) // private key
	y := suite.Point().Mul(x, nil) // public key

	return &BasicWallet{
		x:       x,
		y:       y,
		suite:   suite,
		addr:    "",
		version: fmt.Sprintf("%d", version),
	}
}

// GetPublicKey getter public key
func (w *BasicWallet) GetPublicKey() ([]byte, error) {

	yb, err := w.y.MarshalBinary()
	if err != nil {
		return []byte{}, fmt.Errorf("failed to marshal public key %v", err)
	}

	return yb, nil
}

// GetVersion getter versionn
func (w *BasicWallet) GetVersion() string {
	return w.version
}

// Address from wallet public key
func (w *BasicWallet) Address() (string, error) {

	if w.addr != "" {
		return w.addr, nil
	}

	publicbytes, err := w.y.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key %v", err)
	}

	out := make([]byte, len(publicbytes))
	salsa20.XORKeyStream(out, publicbytes, nonce[:], &key)

	w.addr = hex.EncodeToString(out)

	return w.addr, nil
}

// Signature for payload
func (w *BasicWallet) Signature(payload []byte) ([]byte, error) {

	random := random.New()
	v := w.suite.Scalar().Pick(random)
	T := w.suite.Point().Mul(v, nil)

	c, err := hashSchnorr(w.suite, payload, T)
	if err != nil {
		return nil, fmt.Errorf("failed to return secret from point %v", err)
	}

	r := w.suite.Scalar()
	r.Mul(w.x, c).Sub(v, r)

	buf := bytes.Buffer{}
	sig := sigWallet{c, r}
	err = w.suite.Write(&buf, &sig)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to write signature to buffer %v", err)
	}

	return buf.Bytes(), nil
}

// VerifySignature check signature against payload
func (w *BasicWallet) VerifySignature(payload, signature []byte) error {

	buf := bytes.NewBuffer(signature)
	sig := sigWallet{}
	err := w.suite.Read(buf, &sig)
	if err != nil {
		return fmt.Errorf("failed to decode signature wallet from signature %v", err)
	}

	r := sig.R
	c := sig.C

	var P, T kyber.Point
	P = w.suite.Point()
	T = w.suite.Point()
	T.Add(T.Mul(r, nil), P.Mul(c, w.y))

	c, err = hashSchnorr(w.suite, payload, T)
	if err != nil {
		return fmt.Errorf("failed to return secret from point %v", err)
	} else if !c.Equal(sig.C) {
		return ErrSignatureMisMatch
	}

	return nil
}

// MarshalToFile export wallet to file
func (w *BasicWallet) MarshalToFile(path string) error {

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
func UnmarshalFromFile(path string) (*BasicWallet, error) {

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

	var w BasicWallet
	w.suite = edwards25519.NewBlakeSHA256Ed25519()

	w.x = w.suite.Scalar()
	w.y = w.suite.Point()

	err = w.x.UnmarshalBinary(export.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key %v", err)
	}

	err = w.y.UnmarshalBinary(export.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key %v", err)
	}

	return &w, nil
}

func createExportWallet(w *BasicWallet) (*exportWallet, error) {

	privatebytes, err := w.x.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key %v", err)
	}

	publicbytes, err := w.y.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key %v", err)
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

func hashSchnorr(suite suite, payload []byte, p kyber.Point) (kyber.Scalar, error) {

	xb, err := p.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key bytes %v", err)
	}

	c := suite.XOF(xb)
	_, err = c.Write(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to write payload to point %v", err)
	}

	return suite.Scalar().Pick(c), nil
}
