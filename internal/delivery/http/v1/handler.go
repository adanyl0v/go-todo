package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/adanyl0v/go-todo/internal/services"
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
	auth   services.AuthService
	// Still used by auth middleware but need to be refactored.
	pgPool        *pgxpool.Pool
	jwtSigningKey []byte
}

func New(
	logger zerolog.Logger,
	pgPool *pgxpool.Pool,
	jwtSigningKey []byte,
	authService services.AuthService,
) Handler {
	return &handlerImpl{
		logger:        logger,
		pgPool:        pgPool,
		jwtSigningKey: jwtSigningKey,
		auth:          authService,
	}
}
