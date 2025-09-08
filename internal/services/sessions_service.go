package services

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/adanyl0v/go-todo/internal/models"
)

type sessionServiceImpl struct {
	logger zerolog.Logger
	pgPool *pgxpool.Pool
}

func NewSessionService(
	logger zerolog.Logger,
	pgPool *pgxpool.Pool,
) SessionService {
	return &sessionServiceImpl{
		logger: logger,
		pgPool: pgPool,
	}
}

func (s *sessionServiceImpl) GetSessionByID(ctx context.Context, sessionID string) (*models.Session, error) {
	session := &models.Session{
		ID: sessionID,
	}

	const selectSessionByIDQuery = `
SELECT user_id,
       fingerprint,
       refresh_token,
       expires_at,
       created_at,
       updated_at
FROM sessions
WHERE id = $1
`
	err := s.pgPool.QueryRow(
		ctx,
		selectSessionByIDQuery,
		session.ID,
	).Scan(
		&session.UserID,
		&session.Fingerprint,
		&session.RefreshToken,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.logger.Error().
				Str("session_id", session.ID).
				Msg("session not found")
			return nil, ErrSessionNotFound
		}

		s.logger.Error().
			Err(err).
			Str("session_id", session.ID).
			Msg("failed to select session by id")
		return nil, err
	}
	s.logger.Debug().
		Str("session_id", session.ID).
		Time("expires_at", session.ExpiresAt).
		Msg("selected session by id")

	s.logger.Info().
		Str("session_id", session.ID).
		Msg("session found")
	return session, nil
}
