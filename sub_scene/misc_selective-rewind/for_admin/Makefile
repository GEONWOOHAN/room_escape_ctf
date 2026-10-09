PYTHON ?= python3
CC ?= gcc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic

VM_SRC := author/vm_src/replay_vm.c
BUILD_DIR := .build/for_user
VM_BIN := $(BUILD_DIR)/replay_vm

.PHONY: all build generate test release clean

all: test

build: $(VM_BIN)

$(VM_BIN): $(VM_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -static -s -o $@ $<

generate: $(VM_BIN)
	$(PYTHON) author/generator/generate.py

test: generate
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s author/tests -p 'test_*.py' -v

release: build
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) author/generator/generate.py --publish

clean:
	rm -rf .build solution/generated author/tests/__pycache__ solution/solver/__pycache__
	rm -rf author/program_src/__pycache__ author/generator/__pycache__
