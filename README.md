# Безопасный сервис аутентификации на Go

В этом задании я сделал небольшой REST API для регистрации и авторизации пользователей.

В сервисе есть четыре эндпоинта:

| Метод | Адрес | Описание |
|---|---|---|
| `POST` | `/register` | регистрация пользователя |
| `POST` | `/login` | вход и получение JWT-токена |
| `GET` | `/profile` | получение профиля по JWT-токену |
| `GET` | `/health` | проверка работы сервиса |

## Что использовано

- Go и стандартный пакет `net/http`;
- PostgreSQL;
- Docker Compose для запуска базы;
- bcrypt для хеширования паролей;
- JWT для авторизации;
- параметризованные SQL-запросы для защиты от SQL-инъекций.

## Структура проекта

```text
secure-service/
├── main.go              # запуск сервера и маршруты
├── handlers.go          # обработчики запросов
├── models.go            # структуры данных
├── database.go          # запросы к PostgreSQL
├── auth.go              # bcrypt и JWT
├── middleware.go        # проверка JWT
├── config.go            # чтение настроек
├── docker-compose.yml   # запуск PostgreSQL
├── init.sql             # создание таблицы users
├── .env.example         # пример настроек
└── .gitignore           # исключение локального файла .env
```

## Запуск проекта

### 1. Создать `.env`

В PowerShell:

```powershell
Copy-Item .env.example .env
```

После этого нужно открыть `.env` и заменить значение `JWT_SECRET` на свою случайную строку длиной не меньше 32 символов.

Пример генерации секрета:

```powershell
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
[Convert]::ToBase64String($bytes)
$rng.Dispose()
```

Полученную строку нужно вставить в `.env`:

```text
JWT_SECRET=сюда_вставить_сгенерированную_строку
```

### 2. Запустить PostgreSQL

Сначала нужно запустить Docker Desktop, затем выполнить:

```powershell
docker compose up -d --wait
docker compose ps
```

Контейнер `secure_service_db` должен получить состояние `healthy`.

PostgreSQL доступен на порту `55432`. Этот порт выбран, чтобы не было конфликта с другой базой на стандартном порту `5432`.

### 3. Скачать зависимости и проверить сборку

```powershell
go mod download
go vet ./...
go build .
```

### 4. Запустить сервер

```powershell
go run .
```

Если всё работает, появится сообщение:

```text
secure service is listening on http://localhost:8080
```

Сервер нужно оставить запущенным. Для следующих команд следует открыть второе окно PowerShell.

## Проверка API

### Проверка состояния

```powershell
Invoke-RestMethod -Uri "http://localhost:8080/health" -Method Get
```

Ожидаемый результат — статус `ok`.

### Регистрация

```powershell
$body = @{
    email    = "user@example.com"
    username = "testuser"
    password = "SecurePass123"
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "http://localhost:8080/register" `
    -Method Post `
    -ContentType "application/json" `
    -Body $body
```

В ответе должны появиться `id`, `email`, `username`, дата создания и JWT в поле `access_token`. Пароль и его хеш сервер не возвращает. Полученный токен можно сразу использовать для запроса `/profile`.

### Вход

```powershell
$loginBody = @{
    email    = "user@example.com"
    password = "SecurePass123"
} | ConvertTo-Json

$login = Invoke-RestMethod `
    -Uri "http://localhost:8080/login" `
    -Method Post `
    -ContentType "application/json" `
    -Body $loginBody

$login
```

В ответе находится JWT-токен в поле `access_token`.

### Получение профиля

```powershell
$headers = @{
    Authorization = "Bearer $($login.access_token)"
}

Invoke-RestMethod `
    -Uri "http://localhost:8080/profile" `
    -Method Get `
    -Headers $headers
```

Без заголовка `Authorization` сервер вернёт ошибку `401 Unauthorized`.

## Как обеспечивается безопасность

### Хеширование паролей

Перед сохранением пароль обрабатывается bcrypt:

```go
hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
```

В PostgreSQL хранится хеш, а не исходный пароль. При входе введённый пароль сравнивается с хешем через `bcrypt.CompareHashAndPassword`.

### Защита от SQL-инъекций

В SQL-запросах используются параметры `$1`, `$2`, `$3`:

```go
query := `SELECT id, email, username, password_hash, created_at
          FROM users WHERE email = $1`

db.QueryRowContext(ctx, query, email)
```

SQL-запрос и пользовательское значение передаются отдельно, поэтому введённый текст не становится частью команды SQL.

### Проверка JWT

После входа сервер выдаёт подписанный JWT. Для доступа к `/profile` middleware проверяет:

- наличие заголовка `Authorization: Bearer <token>`;
- подпись токена;
- алгоритм подписи;
- срок действия токена.

Если токен отсутствует, изменён или просрочен, сервер возвращает `401`.

## Проверка пароля в базе

```powershell
docker exec secure_service_db psql -U postgres -d secure_service `
  -c "SELECT email, password_hash FROM users;"
```

Вместо `SecurePass123` в таблице должна быть строка bcrypt, которая начинается с `$2a$` или `$2b$`.

## Остановка проекта

Сервер останавливается сочетанием `Ctrl+C`.

Контейнер базы можно остановить командой:

```powershell
docker compose down
```
