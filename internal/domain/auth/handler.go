package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/alexedwards/argon2id"
	"github.com/google/uuid"

	"github.com/jackc/pgerrcode"

	"github.com/adanyl0v/go-todo-list/internal/domain/sessions"
	"github.com/adanyl0v/go-todo-list/internal/domain/users"
)

const (
	accessTokenCookie  = "access_token"
	refreshTokenCookie = "refresh_token"
)

type Handler interface {
	HandleLogin(c *gin.Context)
	HandleRefresh(c *gin.Context)
	HandleRegister(c *gin.Context)
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

type loginRequest struct {
	Email    string `json:"email" binding:"required,email,max=255"`
	Password string `json:"password" binding:"required,min=6,max=255"`
}

func (h *handlerImpl) HandleLogin(c *gin.Context) {
	var req loginRequest
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
		Msg("login request")

	now := time.Now()
	user := users.User{
		Email:     req.Email,
		UpdatedAt: now,
	}

	const selectUserQuery = `
SELECT id, password
FROM users WHERE email = $1
`
	err = h.pgPool.QueryRow(
		c,
		selectUserQuery,
		req.Email,
	).Scan(
		&user.ID,
		&user.Password,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			h.logger.Error().
				Err(err).
				Msg("user not found")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		h.logger.Error().
			Err(err).
			Msg("failed to select user")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	match, err := argon2id.ComparePasswordAndHash(req.Password, user.Password)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to compare password")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	if !match {
		h.logger.Error().
			Msg("password mismatch")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	h.logger.Debug().
		Str("id", user.ID).
		Msg("found user")

	browserFingerprint, err := generateFingerprint(c)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to generate fingerprint")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	const deleteSessionsQuery = `
DELETE FROM sessions
WHERE user_id = $1 AND fingerprint = $2
`
	commandTag, err := h.pgPool.Exec(
		c,
		deleteSessionsQuery,
		user.ID,
		browserFingerprint,
	)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to delete sessions")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	h.logger.Debug().
		Int64("affected", commandTag.RowsAffected()).
		Msg("deleted sessions with the same browser fingerprint")

	now = time.Now()
	session := sessions.Session{
		UserID:      user.ID,
		Fingerprint: browserFingerprint,
		ExpiresAt:   now.Add(h.jwtRefreshTokenTTL),
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	sessionUUID, err := uuid.NewV7()
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to generate session uuid")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	session.ID = sessionUUID.String()

	refreshToken, err := generateRefreshToken()
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to generate refresh token")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	session.RefreshToken = refreshToken

	const insertSessionQuery = `
INSERT INTO sessions (id, user_id, fingerprint, refresh_token, expires_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`
	_, err = h.pgPool.Exec(
		c,
		insertSessionQuery,
		session.ID,
		session.UserID,
		session.Fingerprint,
		session.RefreshToken,
		session.ExpiresAt,
		session.CreatedAt,
		session.UpdatedAt,
	)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to insert session")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	h.logger.Debug().
		Str("id", session.ID).
		Msg("inserted session")

	accessToken, err := generateAccessToken(
		session.ID,
		h.jwtIssuer,
		h.jwtAccessTokenTTL,
		h.jwtSigningKey,
	)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to generate access token")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	setJWTCookie(c, accessTokenCookie, accessToken, h.jwtAccessTokenTTL)
	setJWTCookie(c, refreshTokenCookie, session.RefreshToken, h.jwtRefreshTokenTTL)

	h.logger.Info().
		Msg("user logged in")
	c.Status(http.StatusOK)
}

func (h *handlerImpl) HandleRefresh(c *gin.Context) {
	refreshToken, err := c.Cookie(refreshTokenCookie)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to get refresh token cookie")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	session := sessions.Session{
		RefreshToken: refreshToken,
	}

	const selectSessionQuery = `
SELECT id, fingerprint, expires_at
FROM sessions WHERE refresh_token = $1
`
	err = h.pgPool.QueryRow(
		c,
		selectSessionQuery,
		session.RefreshToken,
	).Scan(
		&session.ID,
		&session.Fingerprint,
		&session.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			h.logger.Error().
				Err(err).
				Msg("session not found")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		h.logger.Error().
			Err(err).
			Msg("failed to select session")
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
			Msg("fingerprint mismatch")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if time.Now().After(session.ExpiresAt) {
		h.logger.Error().
			Msg("session expired")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	refreshToken, err = generateRefreshToken()
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to generate refresh token")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	session.RefreshToken = refreshToken

	now := time.Now()
	session.ExpiresAt = now.Add(h.jwtRefreshTokenTTL)
	session.UpdatedAt = now

	const updateSessionQuery = `
UPDATE sessions SET refresh_token = $1, expires_at = $2, updated_at = $3
WHERE id = $4
`
	_, err = h.pgPool.Exec(
		c,
		updateSessionQuery,
		session.RefreshToken,
		session.ExpiresAt,
		session.UpdatedAt,
		session.ID,
	)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to update session")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	h.logger.Debug().
		Str("id", session.ID).
		Msg("updated session")

	accessToken, err := generateAccessToken(
		session.ID,
		h.jwtIssuer,
		h.jwtAccessTokenTTL,
		h.jwtSigningKey,
	)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to generate access token")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	setJWTCookie(c, accessTokenCookie, accessToken, h.jwtAccessTokenTTL)
	setJWTCookie(c, refreshTokenCookie, session.RefreshToken, h.jwtRefreshTokenTTL)

	h.logger.Info().
		Msg("refreshed session")
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

	now := time.Now()
	user := users.User{
		Email:     req.Email,
		CreatedAt: now,
		UpdatedAt: now,
	}

	userUUID, err := uuid.NewV7()
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to generate user uuid")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	user.ID = userUUID.String()

	hash, err := argon2id.CreateHash(req.Password, argon2id.DefaultParams)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to hash password")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	user.Password = hash

	tx, err := h.pgPool.Begin(c)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to begin transaction")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(c)
		} else {
			_ = tx.Commit(c)
		}
	}()

	const insertUserQuery = `
INSERT INTO users (id, email, password, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5)
`
	_, err = tx.Exec(
		c,
		insertUserQuery,
		user.ID,
		user.Email,
		user.Password,
		user.CreatedAt,
		user.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == pgerrcode.UniqueViolation {
				h.logger.Error().
					Err(err).
					Msg("user with this email already exists")
				c.AbortWithStatus(http.StatusConflict)
				return
			}
		}

		h.logger.Error().
			Err(err).
			Msg("failed to insert user")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	h.logger.Debug().
		Str("id", user.ID).
		Msg("inserted user")

	now = time.Now()
	session := sessions.Session{
		UserID:    user.ID,
		ExpiresAt: now.Add(h.jwtRefreshTokenTTL),
		CreatedAt: now,
		UpdatedAt: now,
	}

	sessionUUID, err := uuid.NewV7()
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to generate session uuid")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	session.ID = sessionUUID.String()

	browserFingerprint, err := generateFingerprint(c)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to generate fingerprint")
		c.AbortWithStatus(http.StatusInternalServerError)
	}
	session.Fingerprint = browserFingerprint

	refreshToken, err := generateRefreshToken()
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to generate refresh token")
		c.AbortWithStatus(http.StatusInternalServerError)
	}
	session.RefreshToken = refreshToken

	const insertSessionQuery = `
INSERT INTO sessions (id, user_id, fingerprint, refresh_token, expires_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`
	_, err = tx.Exec(
		c,
		insertSessionQuery,
		session.ID,
		session.UserID,
		session.Fingerprint,
		session.RefreshToken,
		session.ExpiresAt,
		session.CreatedAt,
		session.UpdatedAt,
	)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to insert session")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	h.logger.Debug().
		Str("id", session.ID).
		Msg("inserted session")

	accessToken, err := generateAccessToken(
		session.ID,
		h.jwtIssuer,
		h.jwtAccessTokenTTL,
		h.jwtSigningKey,
	)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to generate access token")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	setJWTCookie(c, accessTokenCookie, accessToken, h.jwtAccessTokenTTL)
	setJWTCookie(c, refreshTokenCookie, session.RefreshToken, h.jwtRefreshTokenTTL)

	h.logger.Info().
		Msg("registered user")
	c.Status(http.StatusCreated)
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

func generateRefreshToken() (string, error) {
	const entropy = 32 // 256-bit
	tokenBytes := make([]byte, entropy)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	return token, nil
}

func generateAccessToken(
	sessionID string,
	issuer string,
	tokenTTL time.Duration,
	signingKey []byte,
) (string, error) {
	now := time.Now()
	unsignedAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   sessionID,
		ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
	})
	accessToken, err := unsignedAccessToken.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}
	return accessToken, nil
}

func setJWTCookie(c *gin.Context, name, value string, maxAge time.Duration) {
	c.SetCookie(name, value, int(maxAge.Seconds()),
		"/", "", false, true)
}
