package config

import "time"

const (
	EnvDev   = "dev"
	EnvProd  = "prod"
	EnvLocal = "local"
)

var globalConfig *Config

func Global() *Config {
	return globalConfig
}

func SetGlobal(cfg *Config) {
	globalConfig = cfg
}

type Config struct {
	Env      string `env:"ENV" env-required:"true"`
	Postgres PostgresConfig
}

type PostgresConfig struct {
	Host           string        `env:"POSTGRES_HOST" env-required:"true"`
	Port           int           `env:"POSTGRES_PORT" env-default:"5432"`
	Username       string        `env:"POSTGRES_USERNAME" env-required:"true"`
	Password       string        `env:"POSTGRES_PASSWORD" env-required:"true"`
	Database       string        `env:"POSTGRES_DATABASE" env-required:"true"`
	SSLMode        string        `env:"POSTGRES_SSL_MODE" env-default:"disable"`
	ConnectTimeout time.Duration `env:"POSTGRES_CONNECT_TIMEOUT" env-default:"10s"`
	PingTimeout    time.Duration `env:"POSTGRES_PING_TIMEOUT" env-default:"10s"`
}
