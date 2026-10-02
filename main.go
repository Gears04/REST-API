package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	config, err := LoadConfig()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	db, err := ConnectDB(config.DatabaseURL)
	if err != nil {
		log.Fatalf("database connection error: %v", err)
	}
	defer db.Close()

	app := &App{
		DB:        db,
		JWTSecret: []byte(config.JWTSecret),
		JWTIssuer: config.JWTIssuer,
		JWTTTL:    config.JWTTTL,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", app.RegisterHandler)
	mux.HandleFunc("POST /login", app.LoginHandler)
	mux.Handle("GET /profile", app.AuthMiddleware(http.HandlerFunc(app.ProfileHandler)))
	mux.HandleFunc("GET /health", app.HealthHandler)

	server := &http.Server{
		Addr:              ":" + config.Port,
		Handler:           SecurityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	shutdownSignal, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("secure service is listening on http://localhost:%s", config.Port)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	<-shutdownSignal.Done()
	log.Print("shutting down server")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown error: %v", err)
	}
}
