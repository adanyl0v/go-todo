package v1

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

type Handler interface {
	HandleLogin(c *gin.Context)
	HandleRefresh(c *gin.Context)
	HandleRegister(c *gin.Context)
	HandleLogout(c *gin.Context)
	HandleAuthMiddleware(c *gin.Context)

	HandleCreateTask(c *gin.Context)
	HandleGetTasks(c *gin.Context)
	HandleUpdateTask(c *gin.Context)
	HandleSetTaskStatus(c *gin.Context)
	HandleDeleteTask(c *gin.Context)
}

type handlerImpl struct {
	logger zerolog.Logger
	pgPool *pgxpool.Pool

	jwtIssuer          string
	jwtSigningKey      []byte
	jwtAccessTokenTTL  time.Duration
	jwtRefreshTokenTTL time.Duration
}

func New(
	logger zerolog.Logger,
	pgPool *pgxpool.Pool,
	jwtIssuer string,
	jwtSigningKey string,
	jwtAccessTokenTTL time.Duration,
	jwtRefreshTokenTTL time.Duration,
) Handler {
	return &handlerImpl{
		logger:             logger,
		pgPool:             pgPool,
		jwtIssuer:          jwtIssuer,
		jwtSigningKey:      []byte(jwtSigningKey),
		jwtAccessTokenTTL:  jwtAccessTokenTTL,
		jwtRefreshTokenTTL: jwtRefreshTokenTTL,
	}
}
