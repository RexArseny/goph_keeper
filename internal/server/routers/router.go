package routers

import (
	"github.com/RexArseny/goph_keeper/internal/server/config"
	"github.com/RexArseny/goph_keeper/internal/server/controllers"
	"github.com/RexArseny/goph_keeper/internal/server/middlewares"
	"github.com/gin-gonic/gin"
)

// NewRouter creates new router.
func NewRouter(
	cfg *config.Config,
	controller controllers.Controller,
	middleware middlewares.Middleware,
) *gin.Engine {
	router := gin.New()
	router.Use(
		gin.Recovery(),
		gin.Logger(),
	)

	router.POST("/registration", controller.Registration)
	router.POST("/auth", controller.Auth)

	groupWithJWT := router.Group("", middleware.GetJWT())
	{
		groupWithJWT.POST("/sync", controller.Sync)
		groupWithJWT.GET("/get", controller.Get)
	}

	return router
}
