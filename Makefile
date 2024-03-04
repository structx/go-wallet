
lint:
	golangci-lint run ./...

deps:
	go mod tidy
	go mod vendor