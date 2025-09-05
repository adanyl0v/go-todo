package config

import "github.com/ilyakaznacheev/cleanenv"

type Reader interface {
	Read() (*Config, error)
}

type EnvReader struct{}

func NewEnvReader() EnvReader {
	return EnvReader{}
}

func (EnvReader) Read() (*Config, error) {
	cfg := new(Config)
	err := cleanenv.ReadEnv(cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}
