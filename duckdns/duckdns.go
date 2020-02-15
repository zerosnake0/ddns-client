package duckdns

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/acme"

	"ddns-client/cert"
)

const (
	link = "https://www.duckdns.org/update?"
)

type resultBody struct {
	Raw    string `json:"raw"`
	OK     bool   `json:"ok"`
	IP     string `json:"ip"`
	IPv6   string `json:"ipv6"`
	Action string `json:"action"`
}

type domainResult struct {
	StatusCode int        `json:"status_code"`
	Body       resultBody `json:"body"`
}

type duckDnsResult struct {
	Time    time.Time     `json:"time"`
	Elapsed time.Duration `json:"elapsed"`

	Domain *domainResult `json:"domain"`

	Acme struct {
		Error string `json:"error,omitempty"`
	} `json:"acme"`
}

type DuckDns struct {
	Interval int    `json:"interval" binding:"min=5"`
	Domain   string `json:"domain" binding:"required"`
	Token    string `json:"token" binding:"len=36"`
	CacheDir string `json:"cache_dir"`

	result *duckDnsResult `json:"-"`
	IP     string         `json:"ip"`

	logger zerolog.Logger `json:"-"`
}

func (d *DuckDns) Wrap(engine *gin.Engine) {
	if d == nil {
		return
	}
	d.logger = log.With().Str("engine", "duckdns").Logger()
	engine.GET("/duckdns", func(c *gin.Context) {
		r := *d.result
		r.Elapsed = time.Now().Sub(r.Time)
		c.JSON(http.StatusOK, r)
	})
	go d.start()
}

func (d *DuckDns) start() {
	for {
		d.once()
		time.Sleep(time.Minute * time.Duration(d.Interval))
	}
}

func (d *DuckDns) update(txt string) (*domainResult, error) {
	values := url.Values{}
	values.Set("domains", d.Domain)
	values.Set("token", d.Token)
	if txt != "" {
		d.logger.Debug().Str("txt", txt).Msg("updating with txt")
		values.Set("txt", txt)
	}
	values.Set("verbose", "true")
	resp, err := http.Get(link + values.Encode())
	if err != nil {
		es := err.Error()
		if d.Token != "" {
			es = strings.ReplaceAll(es, d.Token, "###token###")
		}
		d.logger.Error().Str(zerolog.ErrorFieldName, es).Msg("unable to get")
		return nil, errors.New(es)
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		d.logger.Error().Err(err).Msg("unable to read body")
		return nil, err
	}
	raw := string(b)
	d.logger.Info().Msgf("raw: %s", raw)

	if txt != "" {
		return nil, nil
	}

	var domainRes domainResult
	domainRes.StatusCode = resp.StatusCode
	domainRes.Body.Raw = raw
	if resp.StatusCode == http.StatusOK {
		arr := strings.Split(raw, "\n")
		if arr[0] != "OK" {
			domainRes.Body.OK = false
		} else {
			domainRes.Body.OK = true
			domainRes.Body.IP = arr[1]
			domainRes.Body.IPv6 = arr[2]
			domainRes.Body.Action = arr[3]
		}
	}
	return &domainRes, nil
}

func (d *DuckDns) once() {
	var res duckDnsResult

	// dns
	d.logger.Info().Msg("updating dns...")
	domainRes, err := d.update("")
	if err != nil {
		d.logger.Error().Err(err).Msg("unable to update w/o token")
		return
	}
	d.logger.Info().Msg("dns updated")

	// acme
	if d.CacheDir != "" {
		if err := d.acme(); err != nil {
			d.logger.Error().Err(err).Msg("unable to update acme")
			res.Acme.Error = err.Error()
		}
	}

	res.Time = time.Now()
	res.Domain = domainRes
	d.result = &res
}

func (d *DuckDns) acme() (err error) {
	d.logger.Info().Msg("checking certificate")
	ok, err := cert.CheckCert(d.CacheDir)
	if err != nil {
		return err
	}
	if ok {
		d.logger.Info().Msg("the current certificate is valid")
		return nil
	}
	d.logger.Info().Msg("getting acme client...")
	client, err := cert.GetClient(d.CacheDir)
	if err != nil {
		d.logger.Error().Err(err).Msg("unable to get acme client")
		return err
	}
	d.logger.Info().Msg("got acme client")
	domain := d.Domain + ".duckdns.org"
	if err := cert.CreateCert(client, d.CacheDir, domain, []string{
		domain, "*." + domain,
	}, func(cli *acme.Client, order *acme.Authorization) (*acme.Challenge, error) {
		var chal *acme.Challenge
		for i := range order.Challenges {
			c := order.Challenges[i]
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return nil, fmt.Errorf("no dns challenge available for %q", order.URI)
		}
		cert, err := cli.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return nil, err
		}
		d.logger.Debug().Msgf("dns record: %s", cert)
		if _, err := d.update(cert); err != nil {
			d.logger.Error().Err(err).Str("txt", cert).
				Msg("unable to update with txt")
			return nil, err
		}
		return chal, nil
	}); err != nil {
		// d.logger.Error().Err(err).Msg("unable to create certificate")
		return err
	}
	return nil
}
