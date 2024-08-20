# The name of the binary you want to build
BINARY_NAME := trackportcli

# The source package (main package)
PACKAGE := ./cmd

# Compiler and linker flags
GOFLAGS := -v
LDFLAGS :=

# Default target that runs both generate and build
all: generate build

# Target to run go generate
generate:
	@go generate ./...

# Target to build the Go binary
build:
	@echo "Building ..."
	@go build $(GOFLAGS) -o $(BINARY_NAME) $(PACKAGE)

# Clean up the build artifacts
clean:
	@echo "Cleaning up..."
	@rm -f $(BINARY_NAME)

.PHONY: all generate build clean