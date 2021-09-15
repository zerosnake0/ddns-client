package duckdns

import (
	"context"
	"time"

	"github.com/go-acme/lego/challenge"
	"github.com/go-acme/lego/challenge/dns01"
)

type duckDnsProvider struct {
	client *Client
}

type sequential interface {
	Sequential() time.Duration
}

var _ challenge.Provider = (*duckDnsProvider)(nil)
var _ sequential = (*duckDnsProvider)(nil)

func NewDuckDnsProvider(client *Client) *duckDnsProvider {
	return &duckDnsProvider{
		client: client,
	}
}

func (ddp *duckDnsProvider) Present(domain, token, keyAuth string) error {
	_, txtRecord := dns01.GetRecord(domain, keyAuth)
	return ddp.client.UpdateTxtRecord(context.TODO(), txtRecord, false)
}

func (ddp *duckDnsProvider) CleanUp(domain, token, keyAuth string) error {
	return ddp.client.UpdateTxtRecord(context.TODO(), "", true)
}

func (ddp *duckDnsProvider) Sequential() time.Duration {
	return dns01.DefaultPropagationTimeout
}

func (ddp *duckDnsProvider) Timeout() (timeout, interval time.Duration) {
	return time.Minute * 5, time.Second * 5
}
