package cert

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/rs/zerolog/log"

	"ddns-client/pkg/cache"
)

const (
	privateKey    = "PRIVATE KEY"
	rsaPrivateKey = "RSA PRIVATE KEY"
	ecPrivateKey  = "EC PRIVATE KEY"
)

func LoadKeyFromData(data []byte) (crypto.Signer, error) {
	priv, _ := pem.Decode(data)
	if priv == nil {
		return nil, errors.New("invalid key")
	}
	switch priv.Type {
	case rsaPrivateKey:
		return x509.ParsePKCS1PrivateKey(priv.Bytes)
	case ecPrivateKey:
		return x509.ParseECPrivateKey(priv.Bytes)
	case privateKey:
		o, err := x509.ParsePKCS8PrivateKey(priv.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := o.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("invalid private key")
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("%q is not supported", priv.Type)
	}
}

func encodeECDSAKey(w io.Writer, key *ecdsa.PrivateKey) error {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	pb := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	return pem.Encode(w, pb)
}

func encodeRSAKey(w io.Writer, key *rsa.PrivateKey) error {
	b := x509.MarshalPKCS1PrivateKey(key)
	pb := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}
	return pem.Encode(w, pb)
}

func CreateKey(w io.Writer) (crypto.Signer, error) {
	// TODO: type of key?
	if true {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		if err := encodeECDSAKey(w, key); err != nil {
			return nil, err
		}
		return key, err
	} else {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		if err := encodeRSAKey(w, key); err != nil {
			return nil, err
		}
		return key, err
	}
}

func LoadOrCreateKeyFromCache(ctx context.Context, ch cache.Cache, filename string) (crypto.Signer, error) {
	data, err := ch.Get(ctx, filename)
	switch err {
	case nil:
		signer, err := LoadKeyFromData(data)
		if err != nil {
			log.Error().Err(err).Msg("unable to load private key")
			return nil, err
		}
		return signer, nil
	case cache.ErrCacheMiss:
		var buf bytes.Buffer
		key, err := CreateKey(&buf)
		if err != nil {
			log.Error().Err(err).Msg("unable to create private key")
			return nil, err
		}
		if err := ch.Put(ctx, filename, buf.Bytes()); err != nil {
			log.Error().Err(err).Msg("unable to save private key")
			return nil, err
		}
		return key, nil
	default:
		log.Error().Err(err).Msg("unable to get private key from cache")
		return nil, err
	}
}
