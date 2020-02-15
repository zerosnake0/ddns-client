package user

import (
	"context"
	"crypto"

	"github.com/go-acme/lego/registration"
)

type User interface {
	GetEmail(ctx context.Context) (string, error)

	GetRegistration(ctx context.Context) (*registration.Resource, error)

	GetPrivateKey(ctx context.Context) (crypto.PrivateKey, error)
}

type userWrapper struct {
	user User
}

var _ registration.User = userWrapper{}

func Wrap(u User) *userWrapper {
	return &userWrapper{
		user: u,
	}
}

func (w userWrapper) GetEmail() string {
	email, err := w.user.GetEmail(context.TODO())
	if err != nil {
		return ""
	}
	return email
}

func (w userWrapper) GetRegistration() *registration.Resource {
	src, err := w.user.GetRegistration(context.TODO())
	if err != nil {
		return nil
	}
	return src
}

func (w userWrapper) GetPrivateKey() crypto.PrivateKey {
	pk, err := w.user.GetPrivateKey(context.TODO())
	if err != nil {
		return nil
	}
	return pk
}
