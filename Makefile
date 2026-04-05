PROJECT := cmaper
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj
BIN := $(BUILD_DIR)/$(PROJECT)

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

SRC := \
	src/main.c \
	src/app/app.c \
	src/cli/config.c \
	src/cli/diagnostic.c \
	src/cli/help.c \
	src/cli/parser.c \
	src/cli/raw.c \
	src/cli/validate.c \
	src/core/error.c \
	src/core/log.c \
	src/output/sink.c \
	src/platform/clipboard.c \
	src/platform/fs.c \
	src/platform/terminal.c \
	src/preflight/check.c \
	src/runtime/context.c \
	src/runtime/paths.c \
	src/security/extract.c \
	src/security/nmap_extract.c \
	src/scan/artifact.c \
	src/scan/command.c \
	src/scan/detail.c \
	src/scan/detail_targets.c \
	src/scan/heartbeat.c \
	src/scan/nmap_xml_model.c \
	src/scan/nmap_xml_parse.c \
	src/scan/nmap_xml_utils.c \
	src/scan/options.c \
	src/scan/plan.c \
	src/scan/process.c \
	src/scan/runner.c \
	src/scan/source_identity.c \
	src/snapshot/schema.c \
	src/snapshot/security.c \
	src/snapshot/store.c \
	src/snapshot/write.c \
	src/history/alerts.c \
	src/history/delete.c \
	src/history/diff.c \
	src/history/domain.c \
	src/history/fuzzy.c \
	src/history/query.c \
	src/history/render.c \
	src/history/service.c

OBJ := $(SRC:src/%.c=$(OBJ_DIR)/%.o)

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJ)
	mkdir -p $(dir $@)
	$(CC) $(THREAD_FLAGS) $(OBJ) $(LDFLAGS) $(XML2_LIBS) $(SQLITE_LIBS) $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: src/%.c
	mkdir -p $(dir $@)
	$(CC) $(THREAD_FLAGS) $(CPPFLAGS) $(XML2_CFLAGS) $(SQLITE_CFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
