package main

import (
	"flag"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/natefinch/lumberjack"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/zerosnake0/jzon"
	"gopkg.in/go-playground/validator.v8"

	"ddns-client/duckdns"
)

var (
	port       int
	configPath string
	logPath    string

	config struct {
		DuckDns *duckdns.DuckDns `json:"duckdns"`
	}
)

func init() {
	flag.IntVar(&port, "port", 9000, "port")
	flag.StringVar(&configPath, "config", "config.json", "config path")
	flag.StringVar(&logPath, "log", "", "log path")
	flag.Parse()

	log.Logger = zerolog.New(zerolog.NewConsoleWriter()).
		With().Timestamp().Caller().Logger()

	var w io.Writer
	if logPath == "" {
		w = zerolog.NewConsoleWriter()
	} else {
		w = &lumberjack.Logger{
			Filename:   logPath,
			MaxSize:    1,
			MaxBackups: 3,
			Compress:   true,
		}
	}
	log.Logger = zerolog.New(w).With().Timestamp().Caller().Logger()
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
}

func getEngine() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})
	config.DuckDns.Wrap(engine)
	return engine
}

func main() {
	if err := getEngine().Run(":" + strconv.Itoa(port)); err != nil {
		log.Fatal().Err(err).Msg("exiting")
	}
}
