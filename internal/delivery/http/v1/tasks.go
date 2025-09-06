package v1

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"

	"github.com/adanyl0v/go-todo-list/internal/models"
)

type getTaskResponse struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func newGetTaskResponse(task *models.Task) getTaskResponse {
	return getTaskResponse{
		ID:          task.ID,
		Title:       task.Title,
		Description: task.Description,
		Status:      task.Status,
		CreatedAt:   task.CreatedAt,
		UpdatedAt:   task.UpdatedAt,
	}
}

type createTaskRequest struct {
	Title       string  `json:"title" binding:"required,max=255"`
	Description *string `json:"description,omitempty"`
}

func (h *handlerImpl) HandleCreateTask(c *gin.Context) {
	userIDValue, exists := c.Get(userIDCtxKey)
	if !exists {
		h.logger.Error().Msg("no user id found in context")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	userID, _ := userIDValue.(string)

	var req createTaskRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to bind json")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	now := time.Now()
	task := models.Task{
		UserID:    userID,
		Title:     req.Title,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if req.Description != nil {
		task.Description = *req.Description
	}

	const insertTaskQuery = `
INSERT INTO tasks (user_id, title, description, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5) RETURNING id, status
`
	var taskID int64
	err = h.pgPool.QueryRow(
		c,
		insertTaskQuery,
		task.UserID,
		task.Title,
		task.Description,
		task.CreatedAt,
		task.UpdatedAt,
	).Scan(
		&taskID,
		&task.Status,
	)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to insert task")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	task.ID = strconv.FormatInt(taskID, 10)
	h.logger.Debug().
		Str("id", task.ID).
		Msg("inserted task")

	h.logger.Info().Msg("created task")
	c.JSON(http.StatusCreated, newGetTaskResponse(&task))
}

func (h *handlerImpl) HandleGetTasks(c *gin.Context) {
	userIDValue, exists := c.Get(userIDCtxKey)
	if !exists {
		h.logger.Error().Msg("no user id found in context")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	userID, _ := userIDValue.(string)

	const selectTasksQuery = `
SELECT id, title, description, status, created_at, updated_at
FROM tasks WHERE user_id = $1
`
	rows, err := h.pgPool.Query(
		c,
		selectTasksQuery,
		userID,
	)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to select tasks")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var tasks []models.Task
	for rows.Next() {
		var task models.Task
		err = rows.Scan(
			&task.ID,
			&task.Title,
			&task.Description,
			&task.Status,
			&task.CreatedAt,
			&task.UpdatedAt,
		)
		if err != nil {
			h.logger.Error().
				Err(err).
				Msg("failed to scan task")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		tasks = append(tasks, task)
	}

	err = rows.Err()
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to iterate over rows")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	if len(tasks) == 0 {
		h.logger.Warn().Msg("no tasks found")
		c.Status(http.StatusOK)
		return
	}
	h.logger.Debug().
		Int("count", len(tasks)).
		Msg("selected tasks")

	response := make([]getTaskResponse, len(tasks))
	for i, task := range tasks {
		response[i] = newGetTaskResponse(&task)
	}

	h.logger.Info().Msg("fetched tasks")
	c.JSON(http.StatusOK, response)
}

type updateTaskRequest struct {
	Title       *string `json:"title,omitempty"`
	Description *string `json:"description,omitempty"`
}

func (h *handlerImpl) HandleUpdateTask(c *gin.Context) {
	userIDValue, exists := c.Get(userIDCtxKey)
	if !exists {
		h.logger.Error().Msg("no user id found in context")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	userID, _ := userIDValue.(string)

	var req updateTaskRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to bind json")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	taskID := c.Param("id")
	if taskID == "" {
		h.logger.Error().Msg("no task id provided")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	now := time.Now()
	task := models.Task{
		ID:        taskID,
		UserID:    userID,
		UpdatedAt: now,
	}

	const selectTaskQuery = `
SELECT title, description, status, created_at
FROM tasks WHERE id = $1 AND user_id = $2
`
	err = h.pgPool.QueryRow(
		c,
		selectTaskQuery,
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
			h.logger.Error().
				Err(err).
				Msg("task not found")
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		h.logger.Error().
			Err(err).
			Msg("failed to select task")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	h.logger.Debug().
		Str("id", task.ID).
		Msg("selected task")

	if req.Title == nil && req.Description == nil {
		h.logger.Warn().Msg("no fields to update")
		c.JSON(http.StatusOK, newGetTaskResponse(&task))
		return
	}

	if req.Title != nil {
		task.Title = *req.Title
	}
	if req.Description != nil {
		task.Description = *req.Description
	}

	const updateTaskQuery = `
UPDATE tasks SET title = $1, description = $2, updated_at = $3
WHERE id = $4
`
	_, err = h.pgPool.Exec(
		c,
		updateTaskQuery,
		task.Title,
		task.Description,
		task.UpdatedAt,
		task.ID,
	)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to update task")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	h.logger.Info().Msg("updated task")
	c.JSON(http.StatusOK, newGetTaskResponse(&task))
}

func (h *handlerImpl) HandleSetTaskStatus(c *gin.Context) {
	userIDValue, exists := c.Get(userIDCtxKey)
	if !exists {
		h.logger.Error().Msg("no user id found in context")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	userID, _ := userIDValue.(string)

	taskID := c.Param("id")
	if taskID == "" {
		h.logger.Error().Msg("no task id provided")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	status := c.Query("status")
	if status == "" {
		h.logger.Error().Msg("no status provided")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if status != models.StatusInProgress &&
		status != models.StatusCompleted &&
		status != models.StatusArchived {
		h.logger.Error().
			Str("status", status).
			Msg("invalid status")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	now := time.Now()
	task := models.Task{
		ID:        taskID,
		UserID:    userID,
		Status:    status,
		UpdatedAt: now,
	}

	const updateTaskStatusQuery = `
UPDATE tasks SET status = $1, updated_at = $2
WHERE id = $3 AND user_id = $4
RETURNING title, description, created_at
`
	err := h.pgPool.QueryRow(
		c,
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
			h.logger.Error().
				Err(err).
				Msg("task not found")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		h.logger.Error().
			Err(err).
			Msg("failed to update task")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	h.logger.Debug().
		Str("id", task.ID).
		Msg("updated task")

	h.logger.Info().Msg("updated task status")
	c.JSON(http.StatusOK, newGetTaskResponse(&task))
}

func (h *handlerImpl) HandleDeleteTask(c *gin.Context) {
	userIDValue, exists := c.Get(userIDCtxKey)
	if !exists {
		h.logger.Error().Msg("no user id found in context")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	userID, _ := userIDValue.(string)

	taskID := c.Param("id")
	if taskID == "" {
		h.logger.Error().Msg("no task id provided")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	const deleteTaskQuery = `
DELETE FROM tasks WHERE id = $1 AND user_id = $2
`
	commandTag, err := h.pgPool.Exec(
		c,
		deleteTaskQuery,
		taskID,
		userID,
	)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to delete task")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	h.logger.Debug().
		Str("id", taskID).
		Msg("deleted task")

	if commandTag.RowsAffected() == 0 {
		h.logger.Warn().Msg("task not found")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	h.logger.Info().Msg("deleted task")
	c.Status(http.StatusNoContent)
}
