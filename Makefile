.PHONY: fmt fmt-check run test vet verify

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l .)"

run:
	go run ./cmd/action-control

test:
	go test -race ./...

vet:
	go vet ./...

verify: fmt-check vet test
