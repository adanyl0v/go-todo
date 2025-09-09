package services

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/adanyl0v/go-todo/internal/models"
)

type taskServiceImpl struct {
	logger zerolog.Logger
	pgPool *pgxpool.Pool
}

func NewTaskService(
	logger zerolog.Logger,
	pgPool *pgxpool.Pool,
) TaskService {
	return &taskServiceImpl{
		logger: logger,
		pgPool: pgPool,
	}
}

func (s *taskServiceImpl) CreateTask(ctx context.Context, task *models.Task) (*models.Task, error) {
	now := time.Now()
	task = &models.Task{
		UserID:      task.UserID,
		Title:       task.Title,
		Description: task.Description,
		Status:      models.StatusInProgress,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	const insertTaskQuery = `
INSERT INTO tasks (user_id,
                   title,
                   description,
                   status,
                   created_at,
                   updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id
`
	var taskID int64
	err := s.pgPool.QueryRow(
		ctx,
		insertTaskQuery,
		task.UserID,
		task.Title,
		task.Description,
		task.Status,
		task.CreatedAt,
		task.UpdatedAt,
	).Scan(&taskID)
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to insert task")
		return nil, err
	}
	s.logger.Debug().
		Int64("task_id", taskID).
		Msg("created task")

	s.logger.Info().
		Int64("task_id", taskID).
		Msg("created task")
	task.ID = strconv.FormatInt(taskID, 10)
	return task, nil
}

func (s *taskServiceImpl) GetTasksByUserID(ctx context.Context, userID string, offset, limit uint32) ([]*models.Task, error) {
	if limit == 0 {
		// 32 is just a random number.
		limit = 32
	}

	const selectTaskByUserIDQuery = `
SELECT id,
       title,
       description,
       status,
       created_at,
       updated_at
FROM tasks
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3
`
	rows, err := s.pgPool.Query(
		ctx,
		selectTaskByUserIDQuery,
		userID,
		limit,
		offset,
	)
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to select tasks by user id")
		return nil, err
	}
	defer rows.Close()

	tasks := make([]*models.Task, 0, limit)
	for rows.Next() {
		task := &models.Task{UserID: userID}
		err = rows.Scan(
			&task.ID,
			&task.Title,
			&task.Description,
			&task.Status,
			&task.CreatedAt,
			&task.UpdatedAt,
		)
		if err != nil {
			s.logger.Error().
				Err(err).
				Msg("failed to scan task")
			return nil, err
		}
		tasks = append(tasks, task)
	}

	err = rows.Err()
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to iterate over rows")
		return nil, err
	}

	if len(tasks) == 0 {
		s.logger.Info().
			Str("user_id", userID).
			Msg("no tasks found")
		return nil, ErrTaskNotFound
	}
	s.logger.Debug().
		Int("count", len(tasks)).
		Str("user_id", userID).
		Msg("selected tasks by user id")

	s.logger.Info().
		Int("count", len(tasks)).
		Str("user_id", userID).
		Msg("tasks found")
	return tasks, nil
}

func (s *taskServiceImpl) UpdateTask(ctx context.Context, params UpdateTaskParams) (*models.Task, error) {
	task := &models.Task{
		ID:        params.ID,
		UserID:    params.UserID,
		UpdatedAt: time.Now(),
	}

	const updateTaskQuery = `
UPDATE tasks
SET title = CASE WHEN title <> $1 AND $1 IS NOT NULL THEN $1 ELSE title END,
	description = CASE WHEN description <> $2 AND $2 IS NOT NULL THEN $2 ELSE description END,
	updated_at = $3
WHERE id = $4 AND user_id = $5
RETURNING title, description, status, created_at
`
	err := s.pgPool.QueryRow(
		ctx,
		updateTaskQuery,
		params.Title,
		params.Description,
		task.UpdatedAt,
		task.ID,
		task.UserID,
	).Scan(
		&task.Title,
		&task.Description,
		&task.Status,
		&task.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.logger.Error().
				Str("task_id", task.ID).
				Str("user_id", task.UserID).
				Msg("task not found")
			return nil, ErrTaskNotFound
		}

		s.logger.Error().
			Err(err).
			Str("task_id", task.ID).
			Msg("failed to update task")
		return nil, err
	}
	s.logger.Debug().
		Str("task_id", task.ID).
		Msg("updated task")

	s.logger.Info().
		Str("task_id", task.ID).
		Str("user_id", task.UserID).
		Msg("updated task")
	return task, nil
}

func (s *taskServiceImpl) UpdateTaskStatus(ctx context.Context, params UpdateTaskStatusParams) (*models.Task, error) {
	if params.Status != models.StatusInProgress &&
		params.Status != models.StatusCompleted &&
		params.Status != models.StatusArchived {
		return nil, ErrInvalidTaskStatus
	}

	task := &models.Task{
		ID:        params.ID,
		UserID:    params.UserID,
		Status:    params.Status,
		UpdatedAt: time.Now(),
	}

	const updateTaskStatusQuery = `
UPDATE tasks
SET status = $1,
    updated_at = $2
WHERE id = $3 AND user_id = $4
RETURNING title, description, created_at
`
	err := s.pgPool.QueryRow(
		ctx,
		updateTaskStatusQuery,
		task.Status,
		task.UpdatedAt,
		task.ID,
		task.UserID,
	).Scan(
		&task.Title,
		&task.Description,
		&task.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.logger.Error().
				Str("task_id", task.ID).
				Str("user_id", task.UserID).
				Msg("task not found")
			return nil, ErrTaskNotFound
		}

		s.logger.Error().
			Err(err).
			Str("task_id", task.ID).
			Msg("failed to update task status")
		return nil, err
	}
	s.logger.Debug().
		Str("task_id", task.ID).
		Msg("updated task status")

	s.logger.Info().
		Str("task_id", task.ID).
		Str("user_id", task.UserID).
		Msg("updated task status")
	return task, nil
}

func (s *taskServiceImpl) DeleteTask(ctx context.Context, params DeleteTaskParams) error {
	const deleteTaskQuery = `
DELETE FROM tasks
WHERE id = $1 AND user_id = $2
`
	tag, err := s.pgPool.Exec(
		ctx,
		deleteTaskQuery,
		params.ID,
		params.UserID,
	)
	if err != nil {
		s.logger.Error().
			Err(err).
			Str("task_id", params.ID).
			Msg("failed to delete task")
		return err
	}
	if tag.RowsAffected() == 0 {
		s.logger.Error().
			Str("task_id", params.ID).
			Str("user_id", params.UserID).
			Msg("task not found")
		return ErrTaskNotFound
	}
	s.logger.Debug().
		Str("task_id", params.ID).
		Msg("deleted task")

	s.logger.Info().
		Str("task_id", params.ID).
		Str("user_id", params.UserID).
		Msg("deleted task")
	return nil
}
