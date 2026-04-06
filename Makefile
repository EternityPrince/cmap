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
	src/security/extract_helpers.c \
	src/security/extract_api.c \
	src/security/extract_fingerprint.c \
	src/security/extract_findings.c \
	src/security/extract_surface.c \
	src/security/nmap_extract.c \
	src/security/nmap_extract_mapping.c \
	src/security/nmap_extract_parser.c \
	src/scan/artifact.c \
	src/scan/command.c \
	src/scan/detail.c \
	src/scan/detail_command.c \
	src/scan/detail_command_run.c \
	src/scan/detail_progress.c \
	src/scan/detail_targets.c \
	src/scan/detail_targets_build.c \
	src/scan/detail_targets_dedupe.c \
	src/scan/detail_target.c \
	src/scan/detail_target_parse.c \
	src/scan/heartbeat.c \
	src/scan/nmap_xml_model.c \
	src/scan/nmap_xml_parse_helpers.c \
	src/scan/nmap_xml_parse.c \
	src/scan/nmap_xml_utils.c \
	src/scan/options.c \
	src/scan/plan.c \
	src/scan/process.c \
	src/scan/runner.c \
	src/scan/script_pipeline.c \
	src/scan/source_identity.c \
	src/snapshot/schema.c \
	src/snapshot/sqlite.c \
	src/snapshot/session.c \
	src/snapshot/device_identity.c \
	src/snapshot/device_lookup.c \
	src/snapshot/device_upsert.c \
	src/snapshot/device.c \
	src/snapshot/host_observation.c \
	src/snapshot/host_view.c \
	src/snapshot/host_children.c \
	src/snapshot/host_persist.c \
	src/snapshot/merge.c \
	src/snapshot/security_persist.c \
	src/snapshot/security_aggregate.c \
	src/snapshot/store.c \
	src/snapshot/write.c \
	src/history/alerts.c \
	src/history/delete.c \
	src/history/diff.c \
	src/history/domain.c \
	src/history/fuzzy.c \
	src/history/query_common.c \
	src/history/query_session.c \
	src/history/query_device.c \
	src/history/query_timeline.c \
	src/history/render_common.c \
	src/history/render_sessions.c \
	src/history/render_devices.c \
	src/history/render_timeline.c \
	src/history/render_diff.c \
	src/history/render_posture.c \
	src/history/service_delete.c \
	src/history/service_reports.c \
	src/history/service_diff.c \
	src/history/service_posture.c \
	src/history/service.c

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
