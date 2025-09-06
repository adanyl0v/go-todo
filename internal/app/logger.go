package app

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/adanyl0v/go-todo/internal/config"
)

var globalLogger zerolog.Logger

func InitDefaultLogger() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	zerolog.TimestampFieldName = "timestamp"

	globalLogger = zerolog.New(os.Stdout).
		With().
		Timestamp().
		Caller().
		Int("pid", os.Getpid()).
		Logger()

	globalLogger.Info().Msg("initialized default logger")
}

func MustInitApplicationLogger() {
	cfg := config.Global()

	w := io.Writer(os.Stdout)
	switch cfg.Env {
	case config.EnvDev:
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case config.EnvProd:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case config.EnvLocal:
		zerolog.SetGlobalLevel(zerolog.TraceLevel)

		consoleWriter := zerolog.NewConsoleWriter()
		consoleWriter.TimeFormat = time.DateTime
		consoleWriter.Out = os.Stdout
		w = consoleWriter
	default:
		globalLogger.Error().
			Str("env", cfg.Env).
			Msg("unknown env")
		panic(fmt.Errorf("unknown env: %s", cfg.Env))
	}

	globalLogger = globalLogger.Output(w)
	globalLogger.Info().Msg("initialized application logger")
}
