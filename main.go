package main

import (
	"context"
	"flag"
	"io"
	"io/ioutil"
	stdLog "log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-acme/lego/lego"
	"github.com/natefinch/lumberjack"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"github.com/zerosnake0/jzon"
	"gopkg.in/go-playground/validator.v8"

	"ddns-client/duckdns"
	"ddns-client/pkg/cache"
	ddProvider "ddns-client/pkg/providers/duckdns"
	"ddns-client/pkg/util"
)

var (
	port       int
	configPath string
	logPath    string

	config struct {
		DuckDns struct {
			ddProvider.Config

			Interval int    `json:"interval" binding:"min=5"`
			CacheDir string `json:"cache_dir" binding:"required"`
		} `json:"duckdns"`
	}

	ddCli        *ddProvider.Client
	ddRes        *ddProvider.UpdateResult
	ddCache      cache.Cache
	ddCacheStage cache.Cache
)

func init() {
	flag.IntVar(&port, "port", 9000, "port")
	flag.StringVar(&configPath, "config", "config.json", "config path")
	flag.StringVar(&logPath, "log", "", "log path")
	flag.Parse()

	const timeFmt = "2006-01-02 15:04:05.999"

	var w io.Writer
	if logPath == "" {
		w = zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
			w.TimeFormat = timeFmt
		})
	} else {
		fileWriter := &lumberjack.Logger{
			Filename:   logPath,
			MaxSize:    1,
			MaxBackups: 3,
			Compress:   true,
		}
		w = zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
			w.Out = fileWriter
			w.TimeFormat = timeFmt
		})
		stdLog.SetOutput(fileWriter)
	}
	log.Logger = zerolog.New(w).With().Timestamp().Caller().Logger()
	util.SetLegoLogger(log.Logger)

	getConfig()
}

func getConfig() {
	b, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatal().Err(err).Str("path", configPath).
			Msg("unable to read config")
	}
	if err := jzon.Unmarshal(b, &config); err != nil {
		log.Fatal().Err(err).Msg("bad config file")
	}
	if err := validator.New(&validator.Config{
		TagName:      "binding",
		FieldNameTag: "json",
	}).Struct(&config); err != nil {
		log.Fatal().Err(err).Msg("invalid config file")
	}
	if config.DuckDns.Domain != "" {
		startDuckDns()
	}
}

func startDuckDns() {
	fs := afero.NewBasePathFs(afero.NewOsFs(), config.DuckDns.CacheDir)
	ddCache = cache.NewFsCache(fs)
	ddCacheStage = cache.NewFsCache(afero.NewBasePathFs(fs, "stage"))
	ddCli = ddProvider.NewClient(&config.DuckDns.Config)
	go func(interval int) {
		if interval < 1 {
			interval = 1
		}
		sleepInterval := time.Minute * time.Duration(interval)
		log.Info().Msg("start looping duckdns")
		for {
			ctx, cancel := context.WithTimeout(context.TODO(), time.Minute)
			res, err := ddCli.Update(ctx)
			cancel()
			if err != nil {
				log.Error().Err(err).Msg("unable to update duckdns")
			} else {
				ddRes = &res
			}
			time.Sleep(sleepInterval)
		}
	}(config.DuckDns.Interval)
}

func getEngine() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	gin.ErrorLogger()

	engine.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})
	engine.GET("/duckdns", func(c *gin.Context) {
		res := ddRes
		c.Status(http.StatusOK)
		s := jzon.NewStreamer()
		defer jzon.ReturnStreamer(s)
		s.Reset(c.Writer)
		if res == nil {
			s.Null()
		} else {
			s.ObjectStart().
				Field("elapsed").String(time.Now().Sub(res.Time).String()).
				Field("code").Int(res.Code).
				Field("raw").String(util.LocalByteToString(res.Raw)).
				Field("ok").Bool(res.OK).
				Field("ip").String(util.LocalByteToString(res.IP)).
				Field("ipv6").String(util.LocalByteToString(res.IPv6)).
				Field("action").String(util.LocalByteToString(res.Action)).
				ObjectEnd()
		}
		s.Flush()
		c.Writer.Flush()
	})
	engine.GET("/duckdns/cert", errorHandler(
		func(c *gin.Context) (string, error) {
			var p struct {
				Prod bool `form:"prod"`
			}
			err := c.ShouldBindQuery(&p)
			if err != nil {
				return "KO", err
			}
			var data []byte
			if p.Prod {
				data, err = ddCache.Get(c.Request.Context(), duckdns.DomainCertFile)
			} else {
				data, err = ddCacheStage.Get(c.Request.Context(), duckdns.DomainCertFile)
			}
			return string(data), err
		}))
	engine.GET("/duckdns/cert/update", errorHandler(
		func(c *gin.Context) (string, error) {
			var p struct {
				Prod bool `form:"prod"`
			}
			if err := c.ShouldBindQuery(&p); err != nil {
				return "KO", err
			}
			if p.Prod {
				return "OK", duckdns.Acme(ddCli, lego.LEDirectoryProduction, ddCache)
			} else {
				return "OK", duckdns.Acme(ddCli, lego.LEDirectoryStaging, ddCacheStage)
			}
		}))
	return engine
}

func errorHandler(cb func(c *gin.Context) (string, error)) func(c *gin.Context) {
	return func(c *gin.Context) {
		s, err := cb(c)
		if err != nil {
			c.String(http.StatusOK, err.Error())
			return
		}
		c.String(http.StatusOK, s)
	}
}

func main() {
	engine := getEngine()
	sv := http.Server{
		Addr:    ":" + strconv.Itoa(port),
		Handler: engine,
	}
	if err := sv.ListenAndServe(); err != nil {
		log.Fatal().Err(err).Msg("exiting")
	}
}
