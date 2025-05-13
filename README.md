# Gophr keeper
## Запуск сервера
Необходимо указать переменные среды:
- DATABASE_DSN - имя источника данных для подключение к базе данных
- SERVER_ADDRESS - адрес сервера (значение по умолчанию: localhost:8080)
- PUBLIC_KEY_PATH - путь до открытого ключа для JWT (значение по умолчанию: public.pem)
- PRIVATE_KEY_PATH - путь до закрытого ключа для JWT (значение по умолчанию: private.pem)
- CERTIFICATE_PATH - путь до сертификата для TLS (значение по умолчанию: cert.pem)
- CERTIFICATE_KEY_PATH - путь до закрытого ключа для TLS (значение по умолчанию: key.pem)
```
go run ./cmd/server/main.go 
```
## Запуск клиента
Необходимо указать переменные среды:
- SERVER_ADDRESS - адрес сервера (значение по умолчанию: https://localhost:8080)
```
go run ./cmd/client/main.go 
```
## Расчет общего тестового покрытия
```
go test --coverprofile=coverage.out ./...
go tool cover --func=coverage.out
```