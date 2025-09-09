package app

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/danielkov/gin-helmet/ginhelmet"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	ginlogger "github.com/gin-contrib/logger"

	"github.com/adanyl0v/go-todo/internal/config"
	"github.com/adanyl0v/go-todo/internal/delivery/http/v1"
	"github.com/adanyl0v/go-todo/internal/services"
)

func MustListenAndServeHTTP() {
	cfg := config.Global()
	if cfg.Env != config.EnvLocal {
		gin.SetMode(gin.ReleaseMode)
	}

	httpCfg := cfg.HTTP

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(ginhelmet.Default())
	router.Use(newHTTPLogger())
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

func newHTTPLogger() gin.HandlerFunc {
	w := io.Writer(os.Stdout)
	if config.Global().Env == config.EnvLocal {
		cw := zerolog.NewConsoleWriter()
		cw.TimeFormat = time.DateTime
		cw.Out = os.Stdout
		w = cw
	}

	fn := ginlogger.SetLogger(
		ginlogger.WithLogger(func(c *gin.Context, l zerolog.Logger) zerolog.Logger {
			reqUUID, _ := uuid.NewRandom()
			return l.Output(w).
				With().
				Str("id", reqUUID.String()).
				Logger()
		}),
	)
	return fn
}

func registerRoutes(router gin.IRouter) {
	jwtCfg := config.Global().JWT
	authService := services.NewAuthService(
		globalLogger,
		globalPostgresPool,
		jwtCfg.Issuer,
		[]byte(jwtCfg.SigningKey),
		jwtCfg.AccessTokenTTL,
		jwtCfg.RefreshTokenTTL,
	)
	sessionService := services.NewSessionService(
		globalLogger,
		globalPostgresPool,
	)
	taskService := services.NewTaskService(
		globalLogger,
		globalPostgresPool,
	)

	v1Handler := v1.New(
		globalLogger,
		globalPostgresPool,
		authService,
		sessionService,
		taskService,
	)
	router = router.Group("/api/v1")

	authRouter := router.Group("/auth")
	authRouter.POST("/login", v1Handler.HandleLogin)
	authRouter.POST("/refresh", v1Handler.HandleRefresh)
	authRouter.POST("/register", v1Handler.HandleRegister)
	authRouter.POST("/logout", v1Handler.HandleAuthMiddleware, v1Handler.HandleLogout)

	tasksRouter := router.Group("/tasks", v1Handler.HandleAuthMiddleware)
	tasksRouter.GET("", v1Handler.HandleGetTasks)
	tasksRouter.POST("", v1Handler.HandleCreateTask)
	tasksRouter.PUT("/:id", v1Handler.HandleUpdateTask)
	tasksRouter.PATCH("/:id", v1Handler.HandleSetTaskStatus)
	tasksRouter.DELETE("/:id", v1Handler.HandleDeleteTask)
}
