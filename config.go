package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Port        string
	DatabaseURL string
	JWTSecret   string
	JWTIssuer   string
	JWTTTL      time.Duration
}

func LoadConfig() (Config, error) {
	// В production переменные обычно задаёт окружение или secret manager.
	// Для локальной работы удобно дополнительно прочитать файл .env.
	_ = godotenv.Load()

	config := Config{
		Port:        envOrDefault("PORT", "8080"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		JWTIssuer:   envOrDefault("JWT_ISSUER", "secure-service"),
	}

	if config.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	if len(config.JWTSecret) < 32 || config.JWTSecret == "change-this-demo-secret-to-a-long-random-value" {
		return Config{}, errors.New("JWT_SECRET must be changed and contain at least 32 characters")
	}

	ttlMinutes, err := strconv.Atoi(envOrDefault("JWT_TTL_MINUTES", "60"))
	if err != nil || ttlMinutes < 1 || ttlMinutes > 1440 {
		return Config{}, fmt.Errorf("JWT_TTL_MINUTES must be a number from 1 to 1440")
	}
	config.JWTTTL = time.Duration(ttlMinutes) * time.Minute

	return config, nil
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
