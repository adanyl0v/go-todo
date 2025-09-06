package v1

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"

	"github.com/adanyl0v/go-todo-list/internal/models"
)

const (
	userIDCtxKey    = "user_id"
	sessionIDCtxKey = "session_id"
)

func (h *handlerImpl) HandleAuthMiddleware(c *gin.Context) {
	const authHeader = "Authorization"
	header := c.GetHeader(authHeader)
	if header == "" {
		h.logger.Error().Msg("authorization header required")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	const bearerPrefix = "Bearer"
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || parts[0] != bearerPrefix {
		h.logger.Error().Msg("invalid authorization header")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	accessToken := parts[1]
	claims, err := h.parseJWTToken(accessToken)
	if err != nil {
		if !errors.Is(err, jwt.ErrTokenExpired) {
			h.logger.Error().
				Err(err).
				Msg("failed to parse token")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		h.HandleRefresh(c)
		if c.IsAborted() {
			return
		}

		accessToken, _ = c.Cookie(accessTokenCookie)
		claims, err = h.parseJWTToken(accessToken)
		if err != nil {
			h.logger.Error().
				Err(err).
				Msg("failed to parse fresh token")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
	}

	session := models.Session{
		ID: claims.Subject,
	}

	const selectSessionQuery = `
SELECT user_id, fingerprint
FROM sessions WHERE id = $1
`
	err = h.pgPool.QueryRow(
		c,
		selectSessionQuery,
		session.ID,
	).Scan(
		&session.UserID,
		&session.Fingerprint,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			h.logger.Warn().Msg("session not found")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		h.logger.Error().
			Err(err).
			Msg("failed to fetch session")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	browserFingerprint, err := generateFingerprint(c)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to generate fingerprint")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	if browserFingerprint != session.Fingerprint {
		h.logger.Error().
			Err(err).
			Msg("fingerprint mismatch")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	c.Set(userIDCtxKey, session.UserID)
	c.Set(sessionIDCtxKey, session.ID)
	c.Next()
}

func (h *handlerImpl) parseJWTToken(tokenString string) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		return h.jwtSigningKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse token claims")
	}
	return claims, nil
}
