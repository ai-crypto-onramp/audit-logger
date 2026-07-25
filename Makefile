.PHONY: build test run lint cover docker-build docker-run clean verify-chain migrate-up migrate-down

build:
	go build -o bin/audit-event-log ./cmd/audit-event-log

test:
	go test ./internal/... -race -coverprofile=coverage.out -coverpkg=./internal/...

run:
	go run ./cmd/audit-event-log

lint:
	golangci-lint run

cover: test
	go tool cover -func=coverage.out | tail -1

verify-chain:
	go run ./cmd/audit-event-log verify-chain --db $$DB_URL

docker-build:
	docker build -t ai-crypto-onramp/audit-logger .

docker-run:
	docker run --rm -p 8080:8080 ai-crypto-onramp/audit-logger

clean:
	rm -rf bin/ coverage.out

migrate-up:
	go run ./cmd/migrate --up

migrate-down:
	go run ./cmd/migrate --down
