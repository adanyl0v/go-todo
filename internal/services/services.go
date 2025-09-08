package services

import (
	"context"
	"errors"
	"time"
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

	Register(ctx context.Context, params LoginParams) (*LoginResult, error)

	// Logout invalidates all sessions with the given user ID.
	Logout(ctx context.Context, userID string) error
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
