build:
	@if [ "$$(uname -o 2>/dev/null)" = "Msys" ] || [ "$$(uname -s | cut -c1-10)" = "MINGW64_NT" ]; then \
		go build -o main.exe cmd/api/main.go; \
	else \
		go build -o main cmd/api/main.go; \
	fi

# Run the application
run:
	@go run cmd/api/main.go

# Create DB container
docker-run:
	@if docker compose up --build -d 2>/dev/null; then \
		: ; \
	else \
		echo "Falling back to Docker Compose V1"; \
		docker-compose up --build -d; \
	fi

# Shutdown DB container
docker-down:
	@if docker compose down 2>/dev/null; then \
		: ; \
	else \
		echo "Falling back to Docker Compose V1"; \
		docker-compose down; \
	fi

# Clean the binary
clean:
	@echo "Cleaning..."
	@rm -f main

# Live Reload
watch:
	@if command -v air > /dev/null; then \
            air; \
            echo "Watching...";\
        else \
            read -p "Go's 'air' tool is not installed. Do you want to install it? [Y/n] " choice; \
            if [ "$$choice" != "n" ] && [ "$$choice" != "N" ]; then \
                go install github.com/air-verse/air@latest; \
                air; \
                echo "Watching...";\
            else \
                echo "You chose not to install air. Exiting..."; \
                exit 1; \
            fi; \
        fi

# Test the application
test:
	@echo "Testing..."
	@go test ./internal/handlers/... ./internal/database/... -v

.PHONY: build run test docker-run docker-down clean watch
