package user

import (
	"context"
	"crypto"
	"strings"

	"github.com/go-acme/lego/registration"
	"github.com/zerosnake0/jzon"

	"ddns-client/pkg/cache"
	"ddns-client/pkg/cert"
)

const (
	emailFile      = "email.txt"
	accountFile    = "account.json"
	accountKeyFile = "account.pem"
)

type cachedUser struct {
	cache cache.Cache

	reg *registration.Resource
}

var _ User = (*cachedUser)(nil)

func NewCachedUser(cache cache.Cache) *cachedUser {
	return &cachedUser{
		cache: cache,
	}
}

func (usr *cachedUser) GetEmail(ctx context.Context) (string, error) {
	data, err := usr.cache.Get(ctx, emailFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (usr *cachedUser) GetRegistration(ctx context.Context) (*registration.Resource, error) {
	// data, err := usr.cache.Get(ctx, accountFile)
	// switch err {
	// case nil:
	// 	var src registration.Resource
	// 	if err := jzon.Unmarshal(data, &src); err != nil {
	// 		return nil, err
	// 	}
	// 	return &src, nil
	// case cache.ErrCacheMiss:
	// 	return nil, nil
	// default:
	// 	return nil, err
	// }
	return usr.reg, nil
}

func (usr *cachedUser) SetRegistration(ctx context.Context, reg *registration.Resource) error {
	data, err := jzon.Marshal(reg)
	if err != nil {
		return err
	}
	if err := usr.cache.Put(ctx, accountFile, data); err != nil {
		return err
	}
	usr.reg = reg
	return nil
}

func (usr *cachedUser) GetPrivateKey(ctx context.Context) (crypto.PrivateKey, error) {
	return cert.LoadOrCreateKeyFromCache(ctx, usr.cache, accountKeyFile)
}
