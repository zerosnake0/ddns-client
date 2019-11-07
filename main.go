package main

import (
	"flag"
	"net/http"
	"strconv"
	"log"
	"io"
	"io/ioutil"
	"encoding/json"
	"os"

	"gopkg.in/go-playground/validator.v8"
	"github.com/natefinch/lumberjack"
	"github.com/gin-gonic/gin"

	"ddns-client/duckdns"
)

var (
	port       int
	configPath string
	logPath    string
	logWriter  io.Writer = os.Stderr

	config struct {
		DuckDns *duckdns.DuckDns `json:"duckdns"`
	}
)

func init() {
	flag.IntVar(&port, "port", 9000, "port")
	flag.StringVar(&configPath, "interval", "config.json", "config path")
	flag.StringVar(&logPath, "log", "", "log path")
	flag.Parse()

	if logPath != "" {
		logWriter = &lumberjack.Logger{
			Filename:   logPath,
			MaxSize:    1,
			MaxBackups: 3,
			Compress:   true,
		}
	}
	log.SetOutput(logWriter)
	getConfig()
}

func getConfig() {
	b, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(b, &config); err != nil {
		log.Fatal(err)
	}
	if err := validator.New(&validator.Config{
		TagName:      "binding",
		FieldNameTag: "json",
	}).Struct(&config); err != nil {
		log.Fatal(err)
	}
}

func getEngine() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})
	config.DuckDns.Wrap(logWriter, engine)
	return engine
}

func main() {
	log.Fatal(getEngine().Run(":" + strconv.Itoa(port)))
}
