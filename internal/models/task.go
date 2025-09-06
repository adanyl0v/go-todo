package models

import "time"

const (
	StatusInProgress = "in_progress"
	StatusCompleted  = "completed"
	StatusArchived   = "archived"
)

type Task struct {
	ID          string
	UserID      string
	Title       string
	Description string
	Status      string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
