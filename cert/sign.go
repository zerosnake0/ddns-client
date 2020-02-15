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
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/acme"
)

const (
	accountKey    = "acme_account+key.pem"
	domainKey     = "acme_domain+key.pem"
	domainCert    = "acme_domain+cert.pem"
	privateKey    = "PRIVATE KEY"
	rsaPrivateKey = "RSA PRIVATE KEY"
	ecPrivateKey  = "EC PRIVATE KEY"
)

type RetryError struct {
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

func getKey(cacheFileName string) (crypto.Signer, error) {
	data, err := ioutil.ReadFile(cacheFileName)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if true {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, err
			}
			var buf bytes.Buffer
			if err := encodeRSAKey(&buf, key); err != nil {
				return nil, err
			}
			if err := ioutil.WriteFile(cacheFileName, buf.Bytes(), 0600); err != nil {
				return nil, err
			}
			return key, nil
		} else {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, err
			}
			var buf bytes.Buffer
			if err := encodeECDSAKey(&buf, key); err != nil {
				return nil, err
			}
			if err := ioutil.WriteFile(cacheFileName, buf.Bytes(), 0600); err != nil {
				return nil, err
			}
			return key, nil
		}
	}
	priv, _ := pem.Decode(data)
	if priv == nil {
		return nil, fmt.Errorf("invalid key in %q", cacheFileName)
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
			return nil, fmt.Errorf("invalid key in %q", cacheFileName)
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("%q is not supported", priv.Type)
	}
}

func CheckCert(cacheDir string) (bool, error) {
	data, err := ioutil.ReadFile(filepath.Join(cacheDir, domainCert))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	now := time.Now()

	var block *pem.Block
	block, data = pem.Decode(data)
	for ; block != nil; block, data = pem.Decode(data) {
		if block.Type != "CERTIFICATE" {
			return false, fmt.Errorf("block type %q is not certificate",
				block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return false, err
		}
		log.Info().Msgf("----- begin cert -----")
		log.Info().Msgf("version: %d", cert.Version)
		log.Info().Msgf("serial: %v", cert.SerialNumber)
		log.Info().Msgf("issuer: %v", cert.Issuer)
		log.Info().Msgf("subject: %v", cert.Subject)
		log.Info().Msgf("from: %v", cert.NotBefore)
		log.Info().Msgf("to: %v", cert.NotAfter)
		log.Info().Msgf("dns: %v", cert.DNSNames)
		log.Info().Msgf("----- end cert -----")
		if cert.NotAfter.Before(now) {
			return false, nil
		}
	}
	return true, nil
}

func GetClient(cacheDir string) (*acme.Client, error) {
	fi, err := os.Stat(cacheDir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%q is not a directory", cacheDir)
	}
	key, err := getKey(filepath.Join(cacheDir, accountKey))
	if err != nil {
		return nil, err
	}
	log.Debug().Str("url", directoryURL).Msg("acme dir url")
	c := acme.Client{
		Key:          key,
		DirectoryURL: directoryURL,
	}
	acct, err := c.Register(context.TODO(), &acme.Account{}, func(tosURL string) bool {
		return true
	})
	if err != nil {
		if err != acme.ErrAccountAlreadyExists {
			return nil, err
		}
	} else {
		log.Debug().Msgf("%v", acct.Status)
	}
	return &c, nil
}

type createCallback func(cli *acme.Client, authz *acme.Authorization) (
	*acme.Challenge, error)

func CreateCert(cli *acme.Client, cacheDir, cn string, domains []string,
	cb createCallback) error {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	bkOffFunc := func(n int, r *http.Request, resp *http.Response) time.Duration {
		b, err := httputil.DumpResponse(resp, false)
		log.Error().Err(err).Msgf("error response: %s", b)
		cancel()
		return time.Minute
	}

	dir, err := cli.Discover(ctx)
	if err != nil {
		log.Error().Err(err).Msg("unable to discover acme server")
		return err
	}
	log.Debug().Msgf("OrderURL: %q", dir.OrderURL)

	certKey, err := getKey(filepath.Join(cacheDir, domainKey))
	if err != nil {
		return err
	}

	req := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
		DNSNames: domains,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, req, certKey)
	if err != nil {
		return err
	}

	log.Debug().Msg("calling cli.AuthorizeOrder")
	cli.RetryBackoff = bkOffFunc
	authOrder, err := cli.AuthorizeOrder(ctx, acme.DomainIDs(domains...))
	cli.RetryBackoff = nil
	if err != nil {
		log.Error().Err(err).Msg("cli.AuthorizeOrder failed")
		return err
	}
	log.Debug().Str("status", authOrder.Status).
		Str("uri", authOrder.URI).
		Msg("order issued")
	if authOrder.Status == acme.StatusValid {
		return nil
	}
	defer func() {
		for _, u := range authOrder.AuthzURLs {
			order, err := cli.GetAuthorization(ctx, u)
			if err != nil {
				log.Error().Err(err).Str("url", u).Msg("unable to get auth status")
				continue
			}
			if order.Status == acme.StatusPending {
				log.Debug().Str("url", u).Msg("revoking...")
				if err := cli.RevokeAuthorization(ctx, u); err != nil {
					log.Error().Err(err).Str("url", u).Msg("unable to revoke auth")
				}
			}
		}
	}()
	switch authOrder.Status {
	case acme.StatusPending:
		for _, u := range authOrder.AuthzURLs {
			order, err := cli.GetAuthorization(ctx, u)
			if err != nil {
				log.Error().Err(err).Msg("cli.GetAuthorization failed")
				return err
			}
			if order.Status != acme.StatusPending {
				continue
			}
			chal, err := cb(cli, order)
			if err != nil {
				log.Error().Err(err).Msg("callback failed")
				return err
			}
			if _, err := cli.Accept(ctx, chal); err != nil {
				log.Error().Err(err).Msg("cli.Accept failed")
				return err
			}
			if _, err := cli.WaitAuthorization(ctx, order.URI); err != nil {
				log.Error().Err(err).Msg("cli.WaitAuthorization failed")
				return err
			}
		}
		o, err := cli.WaitOrder(ctx, authOrder.URI)
		if err != nil {
			log.Error().Err(err).Msg("cli.WaitOrder failed")
			return err
		}
		log.Debug().Msgf("%v", o)
		fallthrough
	case acme.StatusReady:
		log.Debug().Msg("the certificate is ready")
		der, certURL, err := cli.CreateOrderCert(ctx, authOrder.FinalizeURL, csr, true)
		if err != nil {
			log.Error().Err(err).Msg("cli.CreateOrderCert failed")
			return err
		}
		log.Debug().Str("url", certURL).Msg("cert url")
		var pemcert []byte
		for _, derItem := range der {
			b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derItem})
			pemcert = append(pemcert, b...)
		}
		if err := ioutil.WriteFile(filepath.Join(cacheDir, domainCert), pemcert, 0600); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("invalid order status %q", authOrder.Status)
	}
}
