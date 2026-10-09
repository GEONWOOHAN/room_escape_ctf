.PHONY: build solve verify release clean

BUILD_DIR := $(abspath .build/for_user)

build:
	PYTHONDONTWRITEBYTECODE=1 python3 author/build_all.py

solve:
	PYTHONDONTWRITEBYTECODE=1 python3 solution/solve_reference.py

verify: build
	NSST_HANDOUT_DIR=$(BUILD_DIR) PYTHONDONTWRITEBYTECODE=1 python3 author/verify_instance.py

release:
	PYTHONDONTWRITEBYTECODE=1 python3 author/build_all.py --publish

clean:
	rm -rf .build author/__pycache__ solution/__pycache__ solution/solver/__pycache__
