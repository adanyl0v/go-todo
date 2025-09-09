package v1

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

var (
	errInvalidRequestBody      = errors.New("invalid request body")
	errMandatoryCookieNotFound = errors.New("mandatory cookie not found")
)

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func newAPIError(code int, message string) apiError {
	return apiError{
		Code:    code,
		Message: message,
	}
}

func (e apiError) Error() string {
	return e.Message
}

func abort(c *gin.Context, err apiError) {
	c.AbortWithStatusJSON(err.Code, gin.H{"error": err.Message})
}

func newStatusTextError(status int) apiError {
	return newAPIError(status, http.StatusText(status))
}

func newBadRequestError(message string) apiError {
	return newAPIError(http.StatusBadRequest, message)
}

func newUnauthorizedError(message string) apiError {
	return newAPIError(http.StatusUnauthorized, message)
}

func newConflictError(message string) apiError {
	return newAPIError(http.StatusConflict, message)
}
