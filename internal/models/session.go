package models

import "time"

type Session struct {
	ID           string
	UserID       string
	Fingerprint  string
	RefreshToken string
	ExpiresAt    time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
