PROJECT := cmaper
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj
BIN := $(BUILD_DIR)/$(PROJECT)
CMAKE ?= $(shell xcrun --find cmake 2>/dev/null || command -v cmake 2>/dev/null)
LSP_BUILD_DIR ?= build-clangd

CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic
CPPFLAGS ?= -Iinclude
LDFLAGS ?=
LDLIBS ?=
XML2_CFLAGS ?= $(shell pkg-config --cflags libxml-2.0 2>/dev/null)
XML2_LIBS ?= $(shell pkg-config --libs libxml-2.0 2>/dev/null)
SQLITE_CFLAGS ?= $(shell pkg-config --cflags sqlite3 2>/dev/null)
SQLITE_LIBS ?= $(shell pkg-config --libs sqlite3 2>/dev/null)
THREAD_FLAGS ?= -pthread

SRC_LIST_FILE ?= sources.list
SRC ?= $(shell sed -e '/^[[:space:]]*$$/d' $(SRC_LIST_FILE))

OBJ := $(SRC:src/%.c=$(OBJ_DIR)/%.o)

.PHONY: all clean lsp

all: $(BIN)

$(BIN): $(OBJ)
	mkdir -p $(dir $@)
	$(CC) $(THREAD_FLAGS) $(OBJ) $(LDFLAGS) $(XML2_LIBS) $(SQLITE_LIBS) $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: src/%.c
	mkdir -p $(dir $@)
	$(CC) $(THREAD_FLAGS) $(CPPFLAGS) $(XML2_CFLAGS) $(SQLITE_CFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

lsp:
	mkdir -p $(LSP_BUILD_DIR)
	if [ -n "$(CMAKE)" ]; then \
		$(CMAKE) -S . -B $(LSP_BUILD_DIR) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON; \
	else \
		echo "cmake not found, generating compile_commands.json from Makefile flags"; \
		{ \
			printf '[\n'; \
			first=1; \
			for src in $(SRC); do \
				obj="$(OBJ_DIR)/$${src#src/}"; \
				obj="$${obj%.c}.o"; \
				cmd="$(CC) $(THREAD_FLAGS) $(CPPFLAGS) $(XML2_CFLAGS) $(SQLITE_CFLAGS) $(CFLAGS) -c $$src -o $$obj"; \
				if [ $$first -eq 0 ]; then printf ',\n'; fi; \
				first=0; \
				printf '  {"directory":"%s","file":"%s","command":"%s"}' "$(CURDIR)" "$$src" "$$cmd"; \
			done; \
			printf '\n]\n'; \
		} > $(LSP_BUILD_DIR)/compile_commands.json; \
	fi
	ln -sf $(LSP_BUILD_DIR)/compile_commands.json compile_commands.json
