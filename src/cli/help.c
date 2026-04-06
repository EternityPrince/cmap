#include "cmaper/cli/help.h"

#include <stdbool.h>
#include <string.h>

#include "cmaper/core/version.h"

static bool cmaper_cli_print_mode_help(
    FILE *stream,
    const char *program_name,
    const char *topic
) {
    if (topic == NULL) {
        return false;
    }

    if (strcmp(topic, "scan") == 0) {
        fprintf(stream,
            "Usage: %s scan --target <target> [--profile <low|mid|high>] [scan-options]\n"
            "       %s scan <target> [--profile <low|mid|high>] [scan-options]\n",
            program_name,
            program_name);
        return true;
    }

    if (strcmp(topic, "sessions") == 0) {
        fprintf(stream, "Usage: %s sessions [--limit <n>]\n", program_name);
        return true;
    }

    if (strcmp(topic, "session") == 0) {
        fprintf(stream,
            "Usage: %s session --session <session-id>\n"
            "       %s session <session-id>\n",
            program_name,
            program_name);
        return true;
    }

    if (strcmp(topic, "diff") == 0) {
        fprintf(stream,
            "Usage: %s diff --from <session-id> --to <session-id>\n"
            "       %s diff <from-session-id> <to-session-id>\n",
            program_name,
            program_name);
        return true;
    }

    if (strcmp(topic, "diff-global") == 0) {
        fprintf(stream,
            "Usage: %s diff-global --from <session-id> --to <session-id>\n"
            "       %s diff-global <from-session-id> <to-session-id>\n",
            program_name,
            program_name);
        return true;
    }

    if (strcmp(topic, "timeline") == 0) {
        fprintf(stream,
            "Usage: %s timeline --session <session-id> [--device <device-id>] [--limit <n>]\n"
            "       %s timeline <session-id> [device-id]\n",
            program_name,
            program_name);
        return true;
    }

    if (strcmp(topic, "devices") == 0) {
        fprintf(stream,
            "Usage: %s devices --session <session-id> [--limit <n>]\n"
            "       %s devices <session-id>\n",
            program_name,
            program_name);
        return true;
    }

    if (strcmp(topic, "device") == 0) {
        fprintf(stream,
            "Usage: %s device --session <session-id> --device <device-id>\n"
            "       %s device <session-id> <device-id>\n",
            program_name,
            program_name);
        return true;
    }

    if (strcmp(topic, "posture") == 0) {
        fprintf(stream,
            "Usage: %s posture --session <session-id> [--device <device-id>]\n"
            "       %s posture <session-id> [device-id]\n",
            program_name,
            program_name);
        return true;
    }

    if (strcmp(topic, "delete-session") == 0) {
        fprintf(stream,
            "Usage: %s delete-session --session <session-id>\n"
            "       %s delete-session <session-id>\n",
            program_name,
            program_name);
        return true;
    }

    if (strcmp(topic, "delete-all-sessions") == 0) {
        fprintf(stream, "Usage: %s delete-all-sessions\n", program_name);
        return true;
    }

    if (strcmp(topic, "check") == 0) {
        fprintf(stream, "Usage: %s check\n", program_name);
        return true;
    }

    return false;
}

void cmaper_cli_print_help(FILE *stream, const char *program_name, const char *topic) {
    const char *name = program_name != NULL ? program_name : "cmaper";

    if (topic != NULL) {
        if (!cmaper_cli_print_mode_help(stream, name, topic)) {
            fprintf(stream, "Unknown help topic '%s'.\n\n", topic);
        } else {
            fprintf(stream, "\n");
        }
    }

    fprintf(stream,
        "Usage: %s <mode> [options]\n"
        "       %s --check\n"
        "       %s --help [mode]\n"
        "       %s --version\n"
        "\n"
        "Modes:\n"
        "  scan                 Run discovery + detail scan and persist session history\n"
        "  sessions             List scan sessions\n"
        "  session              Show one session summary and hosts\n"
        "  diff                 Compare two sessions with changed hosts\n"
        "  diff-global          Summary diff between two sessions\n"
        "  timeline             Timeline around a session (optional device filter)\n"
        "  devices              List devices seen in a session\n"
        "  device               Show one device history and observations\n"
        "  posture              Security posture summary for a session\n"
        "  delete-session       Delete a single session (interactive confirmation)\n"
        "  delete-all-sessions  Delete all sessions (interactive confirmation)\n"
        "  check                Run local CLI/preflight checks\n"
        "\n"
        "Global options:\n"
        "  -h, --help             Show usage (optional mode topic)\n"
        "  -V, --version          Show version information\n"
        "      --check            Run preflight checks and print report\n"
        "      --dev              Run preflight before executing the selected mode\n"
        "      --xml-only         Scan without SQLite persistence (XML artifacts only)\n"
        "  -v, --verbose          Increase log verbosity (shows phase/info diagnostics)\n"
        "  -q, --quiet            Reduce log verbosity (repeatable)\n"
        "      --format <fmt>     Output format: terminal|markdown|json\n"
        "      --view <view>      Report view: compact|full\n"
        "      --output <target>  Output target: terminal|clipboard|file:<path>\n"
        "      --json             Shortcut for '--format json'\n"
        "      --color            Force color output when terminal supports it\n"
        "      --no-color         Disable color output\n"
        "\n"
        "Mode options:\n"
        "      --target <expr>        Target expression for scan\n"
        "      --profile <lvl>        Scan profile: low|mid|high (default: mid)\n"
        "      --ports <expr>         Exact port expression override\n"
        "      --exact-ports <expr>   Alias for '--ports'\n"
        "      --all-ports            Scan full TCP port range (1-65535) in detail phase\n"
        "      --no-all-ports         Disable full-range detail scan (default)\n"
        "      --no-ping              Disable host discovery ping checks (-Pn)\n"
        "      --ping                 Force ping-based host discovery when applicable\n"
        "      --timing <0..5>        Timing template override\n"
        "      --detail-workers <n>   Detail worker count override\n"
        "      --service-detection    Force service detection\n"
        "      --no-service-detection Disable service detection\n"
        "      --os-detection         Force OS detection\n"
        "      --no-os-detection      Disable OS detection\n"
        "      --sudo                 Force sudo mode\n"
        "      --no-sudo              Disable sudo mode\n"
        "      --spoof-mac <value>    Enable spoofing with specific MAC/random token\n"
        "      --no-spoof-mac         Disable spoofing\n"
        "      --traceroute           Enable traceroute\n"
        "      --no-traceroute        Disable traceroute\n"
        "      --udp-enrichment       Enable UDP enrichment\n"
        "      --no-udp-enrichment    Disable UDP enrichment\n"
        "      --session <id>         Session id (alias: --session-id)\n"
        "      --from <id>            Base session id for diff\n"
        "      --to <id>              Comparison session id for diff\n"
        "      --device <id>          Device id (alias: --device-id)\n"
        "      --limit <n>            Positive integer limit for list modes\n"
        "      --yes                  Compatibility flag for destructive mode automation\n"
        "\n"
        "Examples:\n"
        "  %s scan --target 10.0.0.0/24 --profile mid\n"
        "  %s sessions --limit 20\n"
        "  %s diff <old-session> <new-session> --view full\n"
        "  %s posture <session-id> --format markdown\n"
        "  %s devices <session-id> --format json --output file:/tmp/devices.json\n",
        name,
        name,
        name,
        name,
        name,
        name,
        name,
        name,
        name);
}

void cmaper_cli_print_version(FILE *stream, const char *program_name) {
    const char *name = program_name != NULL ? program_name : "cmaper";

    fprintf(stream, "%s %s\n", name, CMAPER_VERSION_STRING);
}
