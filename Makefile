.PHONY: build test vet fmt run

build:
	go build -o cfprobe ./cmd/cfprobe

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

run:
	go run ./cmd/cfprobe
