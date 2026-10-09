CXX ?= g++
INSTANCE_SEED := $(shell sed -n '1p' instance.seed)
CXXFLAGS := -std=c++20 -O2 -pipe -fPIE -fvisibility=hidden -fstack-protector-strong \
	-D_FORTIFY_SOURCE=2 -DPF_OPCODE_SEED=$(INSTANCE_SEED)ULL \
	-Wall -Wextra -Wpedantic -I./src
LDFLAGS := -pie -Wl,-z,relro,-z,now -lcrypto

BUILD := build
BIN := bin
USER := ../for_user
COMMON := $(BUILD)/core.o $(BUILD)/engine.o

.PHONY: all clean package test

all: $(USER)/phantom_vm $(USER)/checker $(USER)/unwrap \
	$(BIN)/seed_instance $(BIN)/finalize_instance $(BIN)/test_crypto

$(BUILD) $(BIN) $(USER)/profiles $(USER)/samples:
	mkdir -p $@

$(BUILD)/core.o: src/core.cpp src/core.hpp instance.seed | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/engine.o: src/engine.cpp src/engine.hpp src/core.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/main_vm.o: src/main_vm.cpp src/engine.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/main_checker.o: src/main_checker.cpp src/engine.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/main_unwrap.o: src/main_unwrap.cpp src/engine.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/main_seed.o: src/main_seed.cpp src/engine.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/main_instance.o: src/main_instance.cpp src/engine.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/test_crypto.o: tests/test_crypto.cpp src/core.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(USER)/phantom_vm: $(COMMON) $(BUILD)/main_vm.o
	$(CXX) $^ $(LDFLAGS) -o $@
	strip --strip-all $@

$(USER)/checker: $(COMMON) $(BUILD)/main_checker.o
	$(CXX) $^ $(LDFLAGS) -o $@
	strip --strip-all $@

$(USER)/unwrap: $(COMMON) $(BUILD)/main_unwrap.o
	$(CXX) $^ $(LDFLAGS) -o $@
	strip --strip-all $@

$(BIN)/seed_instance: $(COMMON) $(BUILD)/main_seed.o | $(BIN)
	$(CXX) $^ $(LDFLAGS) -o $@

$(BIN)/finalize_instance: $(COMMON) $(BUILD)/main_instance.o | $(BIN)
	$(CXX) $^ $(LDFLAGS) -o $@

$(BIN)/test_crypto: $(BUILD)/core.o $(BUILD)/test_crypto.o | $(BIN)
	$(CXX) $^ $(LDFLAGS) -o $@

package: all | $(USER)/profiles $(USER)/samples
	python3 tools/build_reference.py
	$(BIN)/seed_instance
	$(BIN)/finalize_instance
	python3 tools/generate_samples.py
	chmod 0755 $(USER)/phantom_vm $(USER)/checker $(USER)/unwrap

test: package
	$(BIN)/test_crypto
	python3 tests/test_package.py

clean:
	rm -rf $(BUILD) $(BIN)
	rm -f $(USER)/phantom_vm $(USER)/checker $(USER)/unwrap
	rm -f $(USER)/runtime.snap $(USER)/transcript.commit $(USER)/flag.enc
	rm -f $(USER)/profiles/*.pgo $(USER)/receipt.bin
