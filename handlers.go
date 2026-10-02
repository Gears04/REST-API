package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxRequestBody = 1 << 20 // 1 MiB

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{3,50}$`)

type App struct {
	DB        *sql.DB
	JWTSecret []byte
	JWTIssuer string
	JWTTTL    time.Duration
}

func (app *App) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var request RegisterRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	request.Username = strings.TrimSpace(request.Username)
	if message := validateRegistration(request); message != "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: message})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	exists, err := UserExistsByEmail(ctx, app.DB, request.Email)
	if err != nil {
		log.Printf("check user existence: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "internal server error"})
		return
	}
	if exists {
		writeJSON(w, http.StatusConflict, ErrorResponse{Error: "email or username is already registered"})
		return
	}

	passwordHash, err := HashPassword(request.Password)
	if err != nil {
		log.Printf("hash password: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "internal server error"})
		return
	}

	user, err := CreateUser(ctx, app.DB, request.Email, request.Username, passwordHash)
	if err != nil {
		if IsUniqueViolation(err) {
			// Проверка выше удобна для ответа, но уникальный индекс всё равно обязателен:
			// две параллельные регистрации могут пройти SELECT одновременно.
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: "email or username is already registered"})
			return
		}
		log.Printf("create user: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "internal server error"})
		return
	}

	writeJSON(w, http.StatusCreated, user)
}

func (app *App) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var request LoginRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	if request.Email == "" || request.Password == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "email and password are required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	user, err := GetUserByEmail(ctx, app.DB, request.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Одинаковый ответ для неизвестного email и неверного пароля
			// не позволяет легко перебирать зарегистрированные адреса.
			unauthorized(w, "invalid email or password")
			return
		}
		log.Printf("get user for login: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "internal server error"})
		return
	}

	if !CheckPassword(user.PasswordHash, request.Password) {
		unauthorized(w, "invalid email or password")
		return
	}

	token, err := GenerateToken(user, app.JWTSecret, app.JWTIssuer, app.JWTTTL)
	if err != nil {
		log.Printf("generate token: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "internal server error"})
		return
	}

	writeJSON(w, http.StatusOK, LoginResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int64(app.JWTTTL.Seconds()),
	})
}

func (app *App) ProfileHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, "authentication is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	user, err := GetUserByID(ctx, app.DB, claims.UserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			unauthorized(w, "user no longer exists")
			return
		}
		log.Printf("get profile: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "internal server error"})
		return
	}

	writeJSON(w, http.StatusOK, user)
}

func (app *App) HealthHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := app.DB.PingContext(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unhealthy"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func validateRegistration(request RegisterRequest) string {
	parsedAddress, err := mail.ParseAddress(request.Email)
	if err != nil || parsedAddress.Address != request.Email {
		return "invalid email"
	}
	if !usernamePattern.MatchString(request.Username) {
		return "username must be 3-50 characters and contain only letters, digits, _ or -"
	}

	passwordBytes := len([]byte(request.Password))
	if passwordBytes < 8 || passwordBytes > 72 {
		return "password must be from 8 to 72 bytes"
	}
	if !utf8.ValidString(request.Password) {
		return "password must be valid UTF-8"
	}

	var hasUpper, hasLower, hasDigit bool
	for _, character := range request.Password {
		switch {
		case unicode.IsUpper(character):
			hasUpper = true
		case unicode.IsLower(character):
			hasLower = true
		case unicode.IsDigit(character):
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return "password must contain uppercase, lowercase and digit characters"
	}

	return ""
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return errors.New("request body must contain valid JSON with expected fields")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain exactly one JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write JSON response: %v", err)
	}
}
