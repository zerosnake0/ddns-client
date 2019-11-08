package duckdns

import (
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
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

type duckDnsResult struct {
	Time       time.Time  `json:"time"`
	StatusCode int        `json:"status_code"`
	Body       resultBody `json:"body"`
}

type DuckDns struct {
	Interval int    `json:"interval" binding:"min=5"`
	Domain   string `json:"domain" binding:"required"`
	Token    string `json:"token" binding:"len=36"`

	result *duckDnsResult `json:"-"`
	IP     string         `json:"ip"`
}

func (d *DuckDns) Wrap(logWriter io.Writer, engine *gin.Engine) {
	if d == nil {
		return
	}
	engine.GET("/duckdns", func(c *gin.Context) {
		c.JSON(http.StatusOK, d.result)
	})
	go d.start(logWriter)
}

func (d *DuckDns) start(logWriter io.Writer) {
	logger := log.New(logWriter, "[duckdns]", log.LstdFlags)
	for {
		d.once(logger)
		time.Sleep(time.Minute * time.Duration(d.Interval))
	}
}

func (d *DuckDns) once(logger *log.Logger) {
	logger.Println("updating...")

	values := url.Values{}
	values.Set("domains", d.Domain)
	values.Set("token", d.Token)
	values.Set("verbose", "true")
	resp, err := http.Get(link + values.Encode())
	if err != nil {
		es := err.Error()
		if d.Token != "" {
			es = strings.ReplaceAll(es, d.Token, "###token###")
		}
		logger.Println("unable to get: ", es)
		return
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Printf("unable to read body: %+v", err)
		return
	}
	raw := string(b)
	logger.Printf(raw)
	res := duckDnsResult{
		Time:       time.Now(),
		StatusCode: resp.StatusCode,
		Body: resultBody{
			Raw: raw,
		},
	}
	if resp.StatusCode == http.StatusOK {
		arr := strings.Split(raw, "\n")
		if arr[0] != "OK" {
			res.Body.OK = false
		} else {
			res.Body.OK = true
			res.Body.IP = arr[1]
			res.Body.IPv6 = arr[2]
			res.Body.Action = arr[3]
		}
	}
	d.result = &res
}
