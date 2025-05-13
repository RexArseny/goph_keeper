package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/RexArseny/goph_keeper/internal/server/config"
	"github.com/RexArseny/goph_keeper/internal/server/controllers"
	"github.com/RexArseny/goph_keeper/internal/server/logger"
	"github.com/RexArseny/goph_keeper/internal/server/middlewares"
	"github.com/RexArseny/goph_keeper/internal/server/repository"
	"github.com/RexArseny/goph_keeper/internal/server/routers"
	"github.com/RexArseny/goph_keeper/internal/server/usecases"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

func NewServer() error {
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGTERM,
		syscall.SIGINT,
		syscall.SIGQUIT)
	defer cancel()

	mainLogger, err := logger.InitLogger()
	if err != nil {
		return fmt.Errorf("can not init logger: %w", err)
	}
	defer func() {
		var pathErr *fs.PathError
		if err = mainLogger.Sync(); err != nil && !errors.As(err, &pathErr) {
			log.Printf("Logger sync failed: %s", err)
		}
	}()

	cfg, err := config.Init()
	if err != nil {
		return fmt.Errorf("can not init config: %w", err)
	}

	publicKeyFile, err := os.ReadFile(cfg.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("can not open public.pem file: %w", err)
	}
	publicKey, err := jwt.ParseEdPublicKeyFromPEM(publicKeyFile)
	if err != nil {
		return fmt.Errorf("can not parse public key: %w", err)
	}

	privateKeyFile, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("can not open private.pem file: %w", err)
	}
	privateKey, err := jwt.ParseEdPrivateKeyFromPEM(privateKeyFile)
	if err != nil {
		return fmt.Errorf("can not parse private key: %w", err)
	}

	db, err := repository.NewRepository(
		ctx,
		mainLogger.Named("repository"),
		cfg.DatabaseDSN,
	)
	if err != nil {
		return fmt.Errorf("can not init repository: %w", err)
	}
	defer db.Close()

	interactor := usecases.NewInteractor(ctx, db, mainLogger.Named("interactor"), privateKey)
	controller := controllers.NewController(mainLogger.Named("controller"), interactor)
	middleware := middlewares.NewMiddleware(publicKey, privateKey, mainLogger.Named("middleware"))
	router := routers.NewRouter(cfg, controller, middleware)

	certBytes, err := os.ReadFile(cfg.CertificatePath)
	if err != nil {
		return fmt.Errorf("can not read certificate file: %w", err)
	}

	keyBytes, err := os.ReadFile(cfg.CertificateKeyPath)
	if err != nil {
		return fmt.Errorf("can not read certificate key file: %w", err)
	}

	x509Cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return fmt.Errorf("can not create x509 key pair: %w", err)
	}

	server := &http.Server{
		Addr:    cfg.ServerAddress,
		Handler: router,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{x509Cert},
			MinVersion:   tls.VersionTLS13,
		},
	}

	go func() {
		<-ctx.Done()
		err = server.Shutdown(ctx)
		if err != nil {
			mainLogger.Error("Can not shutdown server", zap.Error(err))
		}
	}()

	err = server.ListenAndServeTLS("", "")
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("can not listen and serve: %w", err)
	}

	fmt.Println("Server shutdown gracefully")

	return nil
}
