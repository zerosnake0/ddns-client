package util

import (
	"fmt"

	"github.com/go-acme/lego/log"
	"github.com/rs/zerolog"
)

type legoLogger struct {
	l zerolog.Logger
}

func (l legoLogger) Fatal(args ...interface{}) {
	l.l.Fatal().Msg(fmt.Sprint(args...))
}

func (l legoLogger) Fatalln(args ...interface{}) {
	l.l.Fatal().Msg(fmt.Sprint(args...))
}

func (l legoLogger) Fatalf(format string, args ...interface{}) {
	l.l.Fatal().Msgf(format, args...)
}

func (l legoLogger) Print(args ...interface{}) {
	l.l.Info().Msg(fmt.Sprint(args...))
}

func (l legoLogger) Println(args ...interface{}) {
	l.l.Info().Msg(fmt.Sprint(args...))
}

func (l legoLogger) Printf(format string, args ...interface{}) {
	l.l.Info().Msgf(format, args...)
}

func SetLegoLogger(logger zerolog.Logger) {
	log.Logger = legoLogger{logger}
}
