package controllers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/RexArseny/goph_keeper/internal/server/middlewares"
	"github.com/RexArseny/goph_keeper/internal/server/models"
	"github.com/RexArseny/goph_keeper/internal/server/repository"
	"github.com/RexArseny/goph_keeper/internal/server/usecases"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Controller is responsible for managing the network interactions of the service.
type Controller struct {
	logger     *zap.Logger
	interactor usecases.Interactor
}

// NewController create new Controller.
func NewController(logger *zap.Logger, interactor usecases.Interactor) Controller {
	return Controller{
		logger:     logger,
		interactor: interactor,
	}
}

// Registration create new user and return JWT.
func (c *Controller) Registration(ctx *gin.Context) {
	data, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": http.StatusText(http.StatusBadRequest)})
		return
	}

	var request models.AuthRequest
	err = json.Unmarshal(data, &request)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": http.StatusText(http.StatusBadRequest)})
		return
	}

	result, err := c.interactor.Registration(ctx, request.Username, request.Password)
	if err != nil {
		if errors.Is(err, repository.ErrUserAlreadyExist) {
			ctx.JSON(http.StatusConflict, gin.H{"error": http.StatusText(http.StatusConflict)})
			return
		}
		c.logger.Error("Can not registr new user", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": http.StatusText(http.StatusInternalServerError)})
		return
	}

	ctx.JSON(http.StatusOK, result)
}

// Auth get user and return JWT.
func (c *Controller) Auth(ctx *gin.Context) {
	data, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": http.StatusText(http.StatusBadRequest)})
		return
	}

	var request models.AuthRequest
	err = json.Unmarshal(data, &request)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": http.StatusText(http.StatusBadRequest)})
		return
	}

	result, err := c.interactor.Auth(ctx, request.Username, request.Password)
	if err != nil {
		if errors.Is(err, repository.ErrInvalidUserOrPassword) {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": http.StatusText(http.StatusUnauthorized)})
			return
		}
		c.logger.Error("Can not auth user", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": http.StatusText(http.StatusInternalServerError)})
		return
	}

	ctx.JSON(http.StatusOK, result)
}

// Sync create or update data in database.
func (c *Controller) Sync(ctx *gin.Context) {
	tokenValue, ok := ctx.Get(middlewares.Authorization)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": http.StatusText(http.StatusUnauthorized)})
		return
	}
	token, ok := tokenValue.(*models.JWT)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": http.StatusText(http.StatusUnauthorized)})
		return
	}

	data, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": http.StatusText(http.StatusBadRequest)})
		return
	}

	var request models.UserData
	err = json.Unmarshal(data, &request)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": http.StatusText(http.StatusBadRequest)})
		return
	}

	err = c.interactor.Sync(ctx, request, token.Username)
	if err != nil {
		c.logger.Error("Can not sync data", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": http.StatusText(http.StatusInternalServerError)})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"status": http.StatusText(http.StatusOK)})
}

// Get return data from database.
func (c *Controller) Get(ctx *gin.Context) {
	tokenValue, ok := ctx.Get(middlewares.Authorization)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": http.StatusText(http.StatusUnauthorized)})
		return
	}
	token, ok := tokenValue.(*models.JWT)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": http.StatusText(http.StatusUnauthorized)})
		return
	}

	result, err := c.interactor.Get(ctx, token.Username)
	if err != nil {
		c.logger.Error("Can not get data", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": http.StatusText(http.StatusInternalServerError)})
		return
	}

	ctx.JSON(http.StatusOK, result)
}
