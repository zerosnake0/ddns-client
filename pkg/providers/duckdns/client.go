package duckdns

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"

	"ddns-client/pkg/util"
)

const (
	updateURL = "https://www.duckdns.org/update"
)

type Config struct {
	Domain string `json:"domain" binding:"required"`
	Token  string `json:"token" binding:"required"`

	HttpClient *http.Client `json:"-"`
}

type Client struct {
	domain string
	token  string
	client *http.Client
}

func NewClient(cfg *Config) *Client {
	c := &Client{
		domain: cfg.Domain,
		token:  cfg.Token,
	}
	if cfg.HttpClient == nil {
		c.client = http.DefaultClient
	} else {
		c.client = cfg.HttpClient
	}
	return c
}

func (c *Client) Domain() string {
	return c.domain
}

func (c *Client) update(ctx context.Context, txt *string, clear *bool) (_ int, _ []byte, err error) {
	values := url.Values{}
	values.Set("domains", c.domain)
	values.Set("token", c.token)
	values.Set("verbose", "true")
	if txt != nil {
		values.Set("txt", *txt)
	}
	if clear != nil {
		values.Set("clear", strconv.FormatBool(*clear))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, updateURL, nil)
	if err != nil {
		return
	}
	req.URL.RawQuery = values.Encode()
	beg := time.Now()
	resp, err := c.client.Do(req)
	elapsed := time.Now().Sub(beg)
	if txt == nil {
		log.Debug().Err(err).Str("elapsed", elapsed.String()).
			Msg("duckdns updated")
	} else {
		log.Debug().Err(err).Str("elapsed", elapsed.String()).
			Str("txt", *txt).Msg("duckdns updated")
	}
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	return resp.StatusCode, body, nil
}

type UpdateResult struct {
	Time time.Time

	Code int
	Raw  []byte

	OK     bool
	IP     []byte
	IPv6   []byte
	Action []byte
}

func (res *UpdateResult) set(code int, body []byte) {
	res.Code = code
	res.Raw = body
	if code != http.StatusOK {
		return
	}
	// OK
	i := bytes.IndexByte(body, '\n')
	if i < 0 {
		return
	}
	res.OK = util.LocalByteToString(body[:i]) == "OK"

	// IP
	body = body[i+1:]
	i = bytes.IndexByte(body, '\n')
	if i < 0 {
		return
	}
	res.IP = body[:i]

	// IPv6
	body = body[i+1:]
	i = bytes.IndexByte(body, '\n')
	if i < 0 {
		return
	}
	res.IPv6 = body[:i]

	// Action
	res.Action = body[i+1:]

	res.Time = time.Now()
}

func (c *Client) Update(ctx context.Context) (res UpdateResult, err error) {
	code, body, err := c.update(ctx, nil, nil)
	if err != nil {
		return
	}
	res.set(code, body)
	return
}

func (c *Client) UpdateTxtRecord(ctx context.Context, txt string, clear bool) error {
	code, body, err := c.update(ctx, &txt, &clear)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("status code %d: %s", code, body)
	}
	return nil
}
