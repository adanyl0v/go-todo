package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/adanyl0v/go-todo/internal/services"
)

const (
	accessTokenCookie  = "access_token"
	refreshTokenCookie = "refresh_token"
)

type loginRequest struct {
	Email    string `json:"email" form:"email" binding:"required,email,max=255"`
	Password string `json:"password" form:"password" binding:"required,min=6,max=255"`
}

func (h *handlerImpl) HandleLogin(c *gin.Context) {
	var req loginRequest
	err := c.ShouldBind(&req)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to bind request body")
		abort(c, newBadRequestError(errInvalidRequestBody.Error()))
		return
	}

	fingerprint, err := generateFingerprint(c)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to generate fingerprint")
		abort(c, newStatusTextError(http.StatusInternalServerError))
		return
	}

	result, err := h.auth.Login(c, services.LoginParams{
		Email:       req.Email,
		Password:    req.Password,
		Fingerprint: fingerprint,
	})
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to login")
		switch {
		case errors.Is(err, services.ErrUserNotFound):
			abort(c, newUnauthorizedError(services.ErrUserNotFound.Error()))
		case errors.Is(err, services.ErrUserPasswordMismatch):
			abort(c, newUnauthorizedError(services.ErrUserPasswordMismatch.Error()))
		default:
			abort(c, newStatusTextError(http.StatusInternalServerError))
		}
		return
	}

	now := time.Now()
	setAccessTokenCookie(c, result.AccessToken, result.AccessTokenExpiresAt.Sub(now))
	setRefreshTokenCookie(c, result.RefreshToken, result.RefreshTokenExpiresAt.Sub(now))

	c.Status(http.StatusOK)
}

func (h *handlerImpl) HandleRefresh(c *gin.Context) {
	refreshToken, err := c.Cookie(refreshTokenCookie)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to get refresh token cookie")
		abort(c, newBadRequestError(errMandatoryCookieNotFound.Error()))
		return
	}

	fingerprint, err := generateFingerprint(c)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to generate fingerprint")
		abort(c, newStatusTextError(http.StatusInternalServerError))
	}

	result, err := h.auth.Refresh(c, services.RefreshParams{
		RefreshToken: refreshToken,
		Fingerprint:  fingerprint,
	})
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to refresh session")
		switch {
		case errors.Is(err, services.ErrSessionNotFound):
			abort(c, newUnauthorizedError(services.ErrSessionNotFound.Error()))
		case errors.Is(err, services.ErrSessionExpired):
			abort(c, newUnauthorizedError(services.ErrSessionExpired.Error()))
		default:
			abort(c, newStatusTextError(http.StatusInternalServerError))
		}
		return
	}

	now := time.Now()
	setAccessTokenCookie(c, result.AccessToken, result.AccessTokenExpiresAt.Sub(now))
	setRefreshTokenCookie(c, result.RefreshToken, result.RefreshTokenExpiresAt.Sub(now))

	c.Status(http.StatusOK)
}

type registerRequest struct {
	loginRequest
}

func (h *handlerImpl) HandleRegister(c *gin.Context) {
	var req registerRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to bind json")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	h.logger.Info().
		Str("email", req.Email).
		Msg("register request")

	fingerprint, err := generateFingerprint(c)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to generate fingerprint")
		abort(c, newStatusTextError(http.StatusInternalServerError))
		return
	}

	result, err := h.auth.Register(c, services.LoginParams{
		Email:       req.Email,
		Password:    req.Password,
		Fingerprint: fingerprint,
	})
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to register user")
		switch {
		case errors.Is(err, services.ErrUserAlreadyExists):
			abort(c, newConflictError(services.ErrUserAlreadyExists.Error()))
		default:
			abort(c, newStatusTextError(http.StatusInternalServerError))
		}
		return
	}

	now := time.Now()
	setAccessTokenCookie(c, result.AccessToken, result.AccessTokenExpiresAt.Sub(now))
	setRefreshTokenCookie(c, result.RefreshToken, result.RefreshTokenExpiresAt.Sub(now))

	c.Status(http.StatusCreated)
}

func (h *handlerImpl) HandleLogout(c *gin.Context) {
	userID, _ := getStringFromContext(c, userIDCtxKey)

	err := h.auth.Logout(c, userID)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to logout")
		abort(c, newStatusTextError(http.StatusInternalServerError))
		return
	}

	clearCookie(c, accessTokenCookie)
	clearCookie(c, refreshTokenCookie)

	c.Status(http.StatusNoContent)
}

func generateFingerprint(c *gin.Context) (string, error) {
	fingerprintBytes, err := json.Marshal(map[string]string{
		"client_ip":  c.ClientIP(),
		"user_agent": c.Request.UserAgent(),
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal json: %w", err)
	}
	return string(fingerprintBytes), nil
}

func getStringFromContext(c *gin.Context, key string) (string, bool) {
	value, exists := c.Get(key)
	if !exists {
		return "", false
	}
	str, ok := value.(string)
	return str, ok
}

func setAccessTokenCookie(c *gin.Context, token string, maxAge time.Duration) {
	// httpOnly must be false to allow client-side JavaScript
	// to read the cookie and send it in the Authorization header.
	const secure, httpOnly = false, false
	c.SetCookie(accessTokenCookie, token, int(maxAge.Seconds()),
		"/", "", secure, httpOnly)
}

func setRefreshTokenCookie(c *gin.Context, token string, maxAge time.Duration) {
	const secure, httpOnly = false, true
	c.SetCookie(refreshTokenCookie, token, int(maxAge.Seconds()),
		"/", "", secure, httpOnly)
}

func clearCookie(c *gin.Context, name string) {
	c.SetCookie(name, "", -1,
		"/", "", false, false)
}
