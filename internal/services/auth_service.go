package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/adanyl0v/go-todo/internal/models"
)

type authServiceImpl struct {
	logger             zerolog.Logger
	pgPool             *pgxpool.Pool
	jwtIssuer          string
	jwtSigningKey      []byte
	jwtAccessTokenTTL  time.Duration
	jwtRefreshTokenTTL time.Duration
}

func NewAuthService(
	logger zerolog.Logger,
	pgPool *pgxpool.Pool,
	jwtIssuer string,
	jwtSigningKey []byte,
	jwtAccessTokenTTL time.Duration,
	jwtRefreshTokenTTL time.Duration,
) AuthService {
	return &authServiceImpl{
		logger:             logger,
		pgPool:             pgPool,
		jwtIssuer:          jwtIssuer,
		jwtSigningKey:      jwtSigningKey,
		jwtAccessTokenTTL:  jwtAccessTokenTTL,
		jwtRefreshTokenTTL: jwtRefreshTokenTTL,
	}
}

func (s *authServiceImpl) Login(ctx context.Context, params LoginParams) (*LoginResult, error) {
	user := models.User{
		Email:     params.Email,
		UpdatedAt: time.Now(),
	}

	const selectUserByEmailQuery = `
SELECT id,
       password
FROM users
WHERE email = $1
`
	err := s.pgPool.QueryRow(
		ctx,
		selectUserByEmailQuery,
		user.Email,
	).Scan(
		&user.ID,
		&user.Password,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.logger.Error().
				Str("email", user.Email).
				Msg("user not found")
			return nil, ErrUserNotFound
		}

		s.logger.Error().
			Err(err).
			Str("email", user.Email).
			Msg("failed to select user by email")
		return nil, err
	}
	s.logger.Debug().
		Str("user_id", user.ID).
		Str("email", user.Email).
		Msg("selected user")

	match, err := argon2id.ComparePasswordAndHash(params.Password, user.Password)
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to compare password")
		return nil, err
	} else if !match {
		s.logger.Error().Msg("passwords do not match")
		return nil, ErrUserPasswordMismatch
	}

	tx, err := s.pgPool.Begin(ctx)
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to begin transaction")
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const deleteSessionsByUserIDQuery = `
DELETE FROM sessions
       WHERE user_id = $1
`
	tag, err := tx.Exec(
		ctx,
		deleteSessionsByUserIDQuery,
		user.ID,
	)
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to delete sessions by user id")
		return nil, err
	}
	s.logger.Debug().
		Str("user_id", user.ID).
		Int64("affected", tag.RowsAffected()).
		Msg("deleted sessions by user id")

	now := time.Now()
	session := models.Session{
		UserID:      user.ID,
		Fingerprint: params.Fingerprint,
		ExpiresAt:   now.Add(s.jwtRefreshTokenTTL),
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	sessionUUID, err := uuid.NewV7()
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to generate session uuid")
		return nil, err
	}
	session.ID = sessionUUID.String()

	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to generate refresh token")
		return nil, err
	}
	session.RefreshToken = refreshToken

	const insertSessionQuery = `
INSERT INTO sessions (id,
                      user_id,
                      fingerprint,
                      refresh_token,
                      expires_at,
                      created_at,
                      updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`
	_, err = tx.Exec(
		ctx,
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
		s.logger.Error().
			Err(err).
			Msg("failed to insert session")
		return nil, err
	}
	s.logger.Debug().
		Str("session_id", session.ID).
		Msg("inserted session")

	accessToken, accessTokenExpiresAt, err := s.generateAccessToken(session.ID)
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to generate access token")
		return nil, err
	}

	err = tx.Commit(ctx)
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to commit transaction")
		return nil, err
	}

	s.logger.Info().
		Str("user_id", user.ID).
		Str("session_id", session.ID).
		Msg("logged in")
	return &LoginResult{
		UserID:                user.ID,
		SessionID:             session.ID,
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  accessTokenExpiresAt,
		RefreshToken:          session.RefreshToken,
		RefreshTokenExpiresAt: session.ExpiresAt,
	}, nil
}

func (s *authServiceImpl) Refresh(ctx context.Context, params RefreshParams) (*LoginResult, error) {
	session := models.Session{
		RefreshToken: params.RefreshToken,
		Fingerprint:  params.Fingerprint,
	}

	const selectSessionByRefreshTokenQuery = `
SELECT id,
       user_id,
       expires_at
FROM sessions
WHERE refresh_token = $1 AND
      fingerprint = $2
`
	err := s.pgPool.QueryRow(
		ctx,
		selectSessionByRefreshTokenQuery,
		session.RefreshToken,
		session.Fingerprint,
	).Scan(
		&session.ID,
		&session.UserID,
		&session.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.logger.Error().Msg("session not found")
			return nil, ErrSessionNotFound
		}

		s.logger.Error().
			Err(err).
			Msg("failed to select session by refresh token")
		return nil, err
	}

	if session.ExpiresAt.Before(time.Now()) {
		s.logger.Error().
			Str("session_id", session.ID).
			Time("expires_at", session.ExpiresAt).
			Msg("session expired")
		return nil, ErrSessionExpired
	}

	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to generate refresh token")
		return nil, err
	}
	session.RefreshToken = refreshToken

	now := time.Now()
	session.ExpiresAt = now.Add(s.jwtRefreshTokenTTL)
	session.UpdatedAt = now

	const updateSessionQuery = `
UPDATE sessions
SET refresh_token = $1,
    expires_at = $2,
    updated_at = $3
WHERE id = $4
`
	_, err = s.pgPool.Exec(
		ctx,
		updateSessionQuery,
		session.RefreshToken,
		session.ExpiresAt,
		session.UpdatedAt,
		session.ID,
	)
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to update session")
		return nil, err
	}
	s.logger.Debug().
		Str("session_id", session.ID).
		Time("expires_at", session.ExpiresAt).
		Msg("updated session")

	accessToken, accessTokenExpiresAt, err := s.generateAccessToken(session.ID)
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to generate access token")
		return nil, err
	}
	s.logger.Info().
		Str("user_id", session.UserID).
		Str("session_id", session.ID).
		Msg("refreshed session")

	return &LoginResult{
		UserID:                session.UserID,
		SessionID:             session.ID,
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  accessTokenExpiresAt,
		RefreshToken:          session.RefreshToken,
		RefreshTokenExpiresAt: session.ExpiresAt,
	}, nil
}

func (s *authServiceImpl) Register(ctx context.Context, params LoginParams) (*LoginResult, error) {
	now := time.Now()
	user := models.User{
		Email:     params.Email,
		CreatedAt: now,
		UpdatedAt: now,
	}

	userUUID, err := uuid.NewV7()
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to generate user uuid")
		return nil, err
	}
	user.ID = userUUID.String()

	passwordHash, err := argon2id.CreateHash(params.Password, argon2id.DefaultParams)
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to hash password")
		return nil, err
	}
	user.Password = passwordHash

	tx, err := s.pgPool.Begin(ctx)
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to begin transaction")
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const insertUserQuery = `
INSERT INTO users (id,
                   email,
                   password,
                   created_at,
                   updated_at)
VALUES ($1, $2, $3, $4, $5)
`
	_, err = tx.Exec(
		ctx,
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
				s.logger.Error().
					Str("email", user.Email).
					Msg("user with this email already exists")
				return nil, ErrUserAlreadyExists
			}
		}

		s.logger.Error().
			Err(err).
			Msg("failed to insert user")
		return nil, err
	}
	s.logger.Debug().
		Str("user_id", user.ID).
		Str("email", user.Email).
		Msg("inserted user")

	now = time.Now()
	session := models.Session{
		UserID:      user.ID,
		Fingerprint: params.Fingerprint,
		ExpiresAt:   now.Add(s.jwtRefreshTokenTTL),
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	sessionUUID, err := uuid.NewV7()
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to generate session uuid")
		return nil, err
	}
	session.ID = sessionUUID.String()

	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to generate refresh token")
		return nil, err
	}
	session.RefreshToken = refreshToken

	const insertSessionQuery = `
INSERT INTO sessions (id,
                      user_id,
                      fingerprint,
                      refresh_token,
                      expires_at,
                      created_at,
                      updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`
	_, err = tx.Exec(
		ctx,
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
		s.logger.Error().
			Err(err).
			Msg("failed to insert session")
		return nil, err
	}
	s.logger.Debug().
		Str("session_id", session.ID).
		Time("expires_at", session.ExpiresAt).
		Msg("inserted session")

	accessToken, accessTokenExpiresAt, err := s.generateAccessToken(session.ID)
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to generate access token")
		return nil, err
	}

	err = tx.Commit(ctx)
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to commit transaction")
		return nil, err
	}

	s.logger.Info().
		Str("user_id", user.ID).
		Str("session_id", session.ID).
		Msg("registered user")
	return &LoginResult{
		UserID:                user.ID,
		SessionID:             session.ID,
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  accessTokenExpiresAt,
		RefreshToken:          session.RefreshToken,
		RefreshTokenExpiresAt: session.ExpiresAt,
	}, nil
}

func (s *authServiceImpl) Logout(ctx context.Context, userID string) error {
	const deleteSessionsByUserIDQuery = `
DELETE FROM sessions
       WHERE user_id = $1
`
	tag, err := s.pgPool.Exec(
		ctx,
		deleteSessionsByUserIDQuery,
		userID,
	)
	if err != nil {
		s.logger.Error().
			Err(err).
			Str("user_id", userID).
			Msg("failed to delete sessions by user id")
		return err
	}
	s.logger.Debug().
		Str("user_id", userID).
		Int64("affected", tag.RowsAffected()).
		Msg("deleted sessions by user id")

	s.logger.Info().
		Str("user_id", userID).
		Msg("logged out")
	return nil
}

func (s *authServiceImpl) ParseJWTToken(token string) (*jwt.RegisteredClaims, error) {
	t, err := jwt.ParseWithClaims(
		token,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return s.jwtSigningKey, nil
		},
		jwt.WithIssuer(s.jwtIssuer),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("token is expired: %w", err)
		}
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := t.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	return claims, nil
}

func (s *authServiceImpl) generateRefreshToken() (string, error) {
	const length = 32
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func (s *authServiceImpl) generateAccessToken(sessionID string) (string, time.Time, error) {
	tokenUUID, err := uuid.NewRandom()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate id: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(s.jwtAccessTokenTTL)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		ID:        tokenUUID.String(),
		Issuer:    s.jwtIssuer,
		Subject:   sessionID,
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
	})

	signed, err := token.SignedString(s.jwtSigningKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}
	return signed, expiresAt, nil
}
