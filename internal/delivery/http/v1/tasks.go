package v1

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/adanyl0v/go-todo/internal/models"
	"github.com/adanyl0v/go-todo/internal/services"
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
	Title       string  `json:"title" form:"title" binding:"required,max=255"`
	Description *string `json:"description,omitempty" form:"description"`
}

func (h *handlerImpl) HandleCreateTask(c *gin.Context) {
	userID, _ := getStringFromContext(c, userIDCtxKey)

	var req createTaskRequest
	err := c.ShouldBind(&req)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to bind request body")
		abort(c, newBadRequestError(errInvalidRequestBody.Error()))
		return
	}
	if req.Description == nil {
		req.Description = new(string)
	}

	task, err := h.tasks.CreateTask(c, &models.Task{
		UserID:      userID,
		Title:       req.Title,
		Description: *req.Description,
	})
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to create task")
		abort(c, newStatusTextError(http.StatusInternalServerError))
		return
	}

	c.JSON(http.StatusCreated, newGetTaskResponse(task))
}

func (h *handlerImpl) HandleGetTasks(c *gin.Context) {
	userID, _ := getStringFromContext(c, userIDCtxKey)

	const base, bitSize = 10, 32
	offset, _ := strconv.ParseUint(c.Query("offset"), base, bitSize)
	limit, _ := strconv.ParseUint(c.Query("limit"), base, bitSize)

	tasks, err := h.tasks.GetTasksByUserID(
		c,
		userID,
		uint32(offset),
		uint32(limit),
	)
	if err != nil {
		if errors.Is(err, services.ErrTaskNotFound) {
			// Return an empty response body.
			c.Status(http.StatusOK)
			return
		}

		h.logger.Error().
			Err(err).
			Msg("failed to get tasks")
		abort(c, newStatusTextError(http.StatusInternalServerError))
		return
	}

	response := make([]getTaskResponse, len(tasks))
	for i, task := range tasks {
		response[i] = newGetTaskResponse(task)
	}
	c.JSON(http.StatusOK, response)
}

type updateTaskRequest struct {
	Title       *string `json:"title,omitempty" form:"title"`
	Description *string `json:"description,omitempty" form:"description"`
}

func (h *handlerImpl) HandleUpdateTask(c *gin.Context) {
	userID, _ := getStringFromContext(c, userIDCtxKey)

	var req updateTaskRequest
	err := c.ShouldBind(&req)
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to bind request body")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	taskID := c.Param("id")
	if taskID == "" {
		h.logger.Error().Msg("no task id provided")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	task, err := h.tasks.UpdateTask(c, services.UpdateTaskParams{
		ID:          taskID,
		UserID:      userID,
		Title:       req.Title,
		Description: req.Description,
	})
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to update task")
		abort(c, newStatusTextError(http.StatusInternalServerError))
		return
	}

	c.JSON(http.StatusOK, newGetTaskResponse(task))
}

func (h *handlerImpl) HandleSetTaskStatus(c *gin.Context) {
	userID, _ := getStringFromContext(c, userIDCtxKey)

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

	task, err := h.tasks.UpdateTaskStatus(c, services.UpdateTaskStatusParams{
		ID:     taskID,
		UserID: userID,
		Status: status,
	})
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to update task status")
		abort(c, newStatusTextError(http.StatusInternalServerError))
		return
	}

	c.JSON(http.StatusOK, newGetTaskResponse(task))
}

func (h *handlerImpl) HandleDeleteTask(c *gin.Context) {
	userID, _ := getStringFromContext(c, userIDCtxKey)

	taskID := c.Param("id")
	if taskID == "" {
		h.logger.Error().Msg("no task id provided")
		abort(c, newBadRequestError(errInvalidRequestBody.Error()))
		return
	}

	err := h.tasks.DeleteTask(c, services.DeleteTaskParams{
		ID:     taskID,
		UserID: userID,
	})
	if err != nil {
		h.logger.Error().
			Err(err).
			Msg("failed to delete task")
		abort(c, newStatusTextError(http.StatusInternalServerError))
		return
	}

	c.Status(http.StatusNoContent)
}
