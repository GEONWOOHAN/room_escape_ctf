.PHONY: all build test release clean

all: test

build:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=author/vendor python3 author/generator/generate.py

test: build
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=author/vendor python3 author/tests/test_e2e.py

release:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=author/vendor python3 author/generator/generate.py --publish

clean:
	rm -rf .build author/__pycache__ author/generator/__pycache__
	rm -rf author/package_builder/__pycache__ solution/solver/__pycache__
