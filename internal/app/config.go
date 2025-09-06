package app

import (
	_ "github.com/joho/godotenv/autoload"

	"github.com/adanyl0v/go-todo/internal/config"
)

func MustReadEnv() {
	cfg, err := config.NewEnvReader().Read()
	if err != nil {
		globalLogger.Error().
			Err(err).
			Msg("failed to read env")
		panic(err)
	}
	globalLogger.Info().
		Str("env", cfg.Env).
		Msg("read env")

	config.SetGlobal(cfg)
}
