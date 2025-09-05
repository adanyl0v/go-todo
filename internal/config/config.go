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
	HTTP     HTTPConfig
	Postgres PostgresConfig
	JWT      JWTConfig
}

type HTTPConfig struct {
	Host            string        `env:"HTTP_HOST" env-required:"true"`
	Port            string        `env:"HTTP_PORT" env-required:"true"`
	ShutdownTimeout time.Duration `env:"HTTP_SHUTDOWN_TIMEOUT" env-default:"5s"`
}

type PostgresConfig struct {
	Host           string        `env:"POSTGRES_HOST" env-required:"true"`
	Port           int           `env:"POSTGRES_PORT" env-required:"true"`
	Username       string        `env:"POSTGRES_USERNAME" env-required:"true"`
	Password       string        `env:"POSTGRES_PASSWORD" env-required:"true"`
	Database       string        `env:"POSTGRES_DATABASE" env-required:"true"`
	SSLMode        string        `env:"POSTGRES_SSL_MODE" env-default:"disable"`
	ConnectTimeout time.Duration `env:"POSTGRES_CONNECT_TIMEOUT" env-default:"10s"`
	PingTimeout    time.Duration `env:"POSTGRES_PING_TIMEOUT" env-default:"10s"`
}

type JWTConfig struct {
	Issuer          string        `env:"JWT_ISSUER" env-required:"true"`
	SigningKey      string        `env:"JWT_SIGNING_KEY" env-required:"true"`
	AccessTokenTTL  time.Duration `env:"JWT_ACCESS_TOKEN_TTL" env-default:"15m"`
	RefreshTokenTTL time.Duration `env:"JWT_REFRESH_TOKEN_TTL" env-default:"43200m"`
}
