package services

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/adanyl0v/go-todo/internal/models"
)

var (
	ErrUserNotFound         = errors.New("user not found")
	ErrUserAlreadyExists    = errors.New("user already exists")
	ErrUserPasswordMismatch = errors.New("user password mismatch")
	ErrSessionNotFound      = errors.New("session not found")
	ErrSessionExpired       = errors.New("session expired")
)

type AuthService interface {
	// Login authenticates the user by email and password.
	//
	// It deletes all sessions with the same user ID and creates
	// a new session and generates a new JWT token pair.
	//
	// It returns ErrUserNotFound if the user with the given
	// email doesn't exist or ErrUserPasswordMismatch if the
	// given password doesn't match the user's password.
	Login(ctx context.Context, params LoginParams) (*LoginResult, error)

	// Refresh updates the session with the given refresh token.
	//
	// It returns ErrSessionNotFound if the session with the
	// given refresh token doesn't exist or ErrSessionExpired
	// if the session is expired.
	Refresh(ctx context.Context, params RefreshParams) (*LoginResult, error)

	// Register a user with the given email and password.
	//
	// It hashes the password, generates a unique ID and creates a
	// session with the given fingerprint and a fresh JWT token pair.
	//
	// It returns ErrUserAlreadyExists if the user
	// with the given email already exists.
	Register(ctx context.Context, params LoginParams) (*LoginResult, error)

	// Logout invalidates all sessions with the given user ID.
	Logout(ctx context.Context, userID string) error

	// ParseJWTToken parses the given JWT token and returns the registered
	// claims or jwt.ErrTokenExpired if the token is expired.
	ParseJWTToken(token string) (*jwt.RegisteredClaims, error)
}

type SessionService interface {
	GetSessionByID(ctx context.Context, sessionID string) (*models.Session, error)
}

type LoginParams struct {
	Email       string
	Password    string
	Fingerprint string
}

type LoginResult struct {
	UserID                string
	SessionID             string
	AccessToken           string
	AccessTokenExpiresAt  time.Time
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
}

type RefreshParams struct {
	RefreshToken string
	Fingerprint  string
}
