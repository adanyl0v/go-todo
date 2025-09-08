package v1

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	userIDCtxKey    = "user_id"
	sessionIDCtxKey = "session_id"
)

func (h *handlerImpl) HandleAuthMiddleware(c *gin.Context) {
	accessToken, err := parseAuthorizationHeader(c)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to parse authorization header")
		abort(c, newUnauthorizedError(err.Error()))
		return
	}

	claims, err := h.auth.ParseJWTToken(accessToken)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to parse access token")
		abort(c, newUnauthorizedError("invalid access token"))
		return
	}

	// Generate a fingerprint before going to the database.
	fingerprint, err := generateFingerprint(c)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to generate fingerprint")
		abort(c, newStatusTextError(http.StatusInternalServerError))
		return
	}

	session, err := h.sessions.GetSessionByID(c, claims.Subject)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to get session")
		abort(c, newStatusTextError(http.StatusInternalServerError))
		return
	}

	if fingerprint != session.Fingerprint {
		h.logger.Error().
			Err(err).
			Msg("fingerprint mismatch")
		abort(c, newUnauthorizedError("fingerprint mismatch"))
		return
	}

	c.Set(userIDCtxKey, session.UserID)
	c.Set(sessionIDCtxKey, session.ID)
	c.Next()
}

func parseAuthorizationHeader(c *gin.Context) (string, error) {
	const authHeader = "Authorization"
	header := c.GetHeader(authHeader)
	if header == "" {
		return "", errors.New("missing authorization header")
	}

	const bearerPrefix = "Bearer"
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || parts[0] != bearerPrefix {
		return "", errors.New("invalid authorization header")
	}
	return parts[1], nil
}
