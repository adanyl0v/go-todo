package config

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
	Env string `env:"ENV" env-required:"true"`
}
