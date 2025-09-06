package app

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/adanyl0v/go-todo/internal/config"
)

var globalPostgresPool *pgxpool.Pool

func MustConnectPostgres() {
	cfg := config.Global().Postgres
	connURL := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.Username, cfg.Password, cfg.Host,
		cfg.Port, cfg.Database, cfg.SSLMode)

	poolCfg, err := pgxpool.ParseConfig(connURL)
	if err != nil {
		globalLogger.Error().
			Err(err).
			Msg("failed to parse postgres config")
		panic(err)
	}
	poolCfg.ConnConfig.ConnectTimeout = cfg.ConnectTimeout

	globalPostgresPool, err = pgxpool.NewWithConfig(context.Background(), poolCfg)
	if err != nil {
		globalLogger.Error().
			Err(err).
			Msg("failed to connect to postgres")
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.PingTimeout)
	defer cancel()

	err = globalPostgresPool.Ping(ctx)
	if err != nil {
		globalLogger.Error().
			Err(err).
			Msg("failed to ping postgres")
		panic(err)
	}
	globalLogger.Info().
		Str("host", cfg.Host).
		Int("port", cfg.Port).
		Msg("connected to postgres")
}

func DisconnectPostgres() {
	globalPostgresPool.Close()
	globalLogger.Info().Msg("disconnected from postgres")
}
