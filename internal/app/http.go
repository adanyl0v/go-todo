package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"

	"github.com/adanyl0v/go-todo-list/internal/config"
	"github.com/adanyl0v/go-todo-list/internal/delivery/http/v1"
)

func MustListenAndServeHTTP() {
	cfg := config.Global()
	if cfg.Env != config.EnvLocal {
		gin.SetMode(gin.ReleaseMode)
	}

	httpCfg := cfg.HTTP

	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	registerRoutes(router)

	server := &http.Server{
		Addr:    net.JoinHostPort(httpCfg.Host, httpCfg.Port),
		Handler: router,
	}

	go func() {
		globalLogger.Info().
			Str("host", httpCfg.Host).
			Str("port", httpCfg.Port).
			Msg("setting up http server")
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			globalLogger.Error().
				Err(err).
				Msg("failed to listen and serve http")
			panic(err)
		}
	}()

	// Wait for the interrupt signal to gracefully
	// shut down the server with a timeout of 5 seconds.
	quit := make(chan os.Signal, 1)
	// kill (no params) by default sends syscall.SIGTERM
	// kill -2 is syscall.SIGINT
	// kill -9 is syscall.SIGKILL but can't be caught, so don't need to add it
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	globalLogger.Info().
		Msg("shutting down http server")

	ctx, cancel := context.WithTimeout(context.Background(), httpCfg.ShutdownTimeout)
	defer cancel()

	err := server.Shutdown(ctx)
	if err != nil {
		globalLogger.Error().
			Err(err).
			Msg("failed to shutdown http server")
		panic(err)
	}
	globalLogger.Info().Msg("shut down http server")
}

func registerRoutes(router gin.IRouter) {
	jwtCfg := config.Global().JWT
	v1Handler := v1.New(
		globalLogger,
		globalPostgresPool,
		jwtCfg.Issuer,
		jwtCfg.SigningKey,
		jwtCfg.AccessTokenTTL,
		jwtCfg.RefreshTokenTTL,
	)
	router = router.Group("/api/v1")

	authRouter := router.Group("/auth")
	authRouter.POST("/login", v1Handler.HandleLogin)
	authRouter.POST("/refresh", v1Handler.HandleRefresh)
	authRouter.POST("/register", v1Handler.HandleRegister)
	authRouter.POST("/logout", v1Handler.HandleAuthMiddleware, v1Handler.HandleLogout)
}
