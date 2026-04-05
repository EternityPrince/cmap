#include "cmaper/scan/process.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cmaper/scan/heartbeat.h"

typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} cmaper_scan_process_buffer_t;

static void cmaper_scan_process_buffer_init(cmaper_scan_process_buffer_t *buffer) {
    if (buffer == NULL) {
        return;
    }

    buffer->data = NULL;
    buffer->size = 0;
    buffer->capacity = 0;
}

static void cmaper_scan_process_buffer_dispose(cmaper_scan_process_buffer_t *buffer) {
    if (buffer == NULL) {
        return;
    }

    if (buffer->data != NULL) {
        free(buffer->data);
        buffer->data = NULL;
    }
    buffer->size = 0;
    buffer->capacity = 0;
}

static cmaper_err_t cmaper_scan_process_buffer_reserve(
    cmaper_scan_process_buffer_t *buffer,
    size_t needed
) {
    size_t next_capacity;
    char *next_data;

    if (buffer == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    if (needed <= buffer->capacity) {
        return CMAPER_OK;
    }

    if (needed > CMAPER_SCAN_PROCESS_CAPTURE_LIMIT) {
        return CMAPER_ERR_OOM;
    }

    next_capacity = buffer->capacity == 0 ? 4096 : buffer->capacity;
    while (next_capacity < needed) {
        size_t grown = next_capacity * 2;
        if (grown <= next_capacity) {
            return CMAPER_ERR_OOM;
        }
        next_capacity = grown;
    }

    if (next_capacity > CMAPER_SCAN_PROCESS_CAPTURE_LIMIT) {
        next_capacity = CMAPER_SCAN_PROCESS_CAPTURE_LIMIT;
    }
    if (next_capacity < needed) {
        return CMAPER_ERR_OOM;
    }

    next_data = (char *) realloc(buffer->data, next_capacity);
    if (next_data == NULL) {
        return CMAPER_ERR_OOM;
    }

    buffer->data = next_data;
    buffer->capacity = next_capacity;
    return CMAPER_OK;
}

static cmaper_err_t cmaper_scan_process_buffer_append(
    cmaper_scan_process_buffer_t *buffer,
    const char *chunk,
    size_t chunk_size
) {
    cmaper_err_t rc;
    size_t needed;

    if (buffer == NULL || (chunk == NULL && chunk_size > 0)) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    if (chunk_size == 0) {
        return CMAPER_OK;
    }

    needed = buffer->size + chunk_size + 1;
    rc = cmaper_scan_process_buffer_reserve(buffer, needed);
    if (rc != CMAPER_OK) {
        return rc;
    }

    memcpy(buffer->data + buffer->size, chunk, chunk_size);
    buffer->size += chunk_size;
    buffer->data[buffer->size] = '\0';

    return CMAPER_OK;
}

static cmaper_err_t cmaper_scan_process_set_nonblocking(int fd) {
    int flags;

    flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        return CMAPER_ERR_IO;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return CMAPER_ERR_IO;
    }

    return CMAPER_OK;
}

static void cmaper_scan_close_fd(int *fd) {
    if (fd == NULL || *fd < 0) {
        return;
    }

    close(*fd);
    *fd = -1;
}

void cmaper_scan_process_result_init(cmaper_scan_process_result_t *result) {
    if (result == NULL) {
        return;
    }

    result->exit_code = -1;
    result->exited_by_signal = false;
    result->signal_number = 0;
    result->stdout_data = NULL;
    result->stdout_size = 0;
    result->stderr_data = NULL;
    result->stderr_size = 0;
}

void cmaper_scan_process_result_dispose(cmaper_scan_process_result_t *result) {
    if (result == NULL) {
        return;
    }

    if (result->stdout_data != NULL) {
        free(result->stdout_data);
        result->stdout_data = NULL;
    }
    result->stdout_size = 0;

    if (result->stderr_data != NULL) {
        free(result->stderr_data);
        result->stderr_data = NULL;
    }
    result->stderr_size = 0;

    result->exit_code = -1;
    result->exited_by_signal = false;
    result->signal_number = 0;
}

static cmaper_err_t cmaper_scan_process_read_pipe(
    int *fd,
    cmaper_scan_process_buffer_t *buffer
) {
    char chunk[4096];

    if (fd == NULL || *fd < 0 || buffer == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    while (true) {
        ssize_t read_size = read(*fd, chunk, sizeof(chunk));
        if (read_size > 0) {
            cmaper_err_t rc = cmaper_scan_process_buffer_append(
                buffer,
                chunk,
                (size_t) read_size
            );
            if (rc != CMAPER_OK) {
                return rc;
            }
            continue;
        }

        if (read_size == 0) {
            cmaper_scan_close_fd(fd);
            return CMAPER_OK;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return CMAPER_OK;
        }

        return CMAPER_ERR_IO;
    }
}

static cmaper_err_t cmaper_scan_process_wait_loop(
    pid_t child_pid,
    int *stdout_fd,
    int *stderr_fd,
    int heartbeat_seconds,
    const char *heartbeat_label,
    cmaper_logger_t *logger,
    cmaper_scan_process_buffer_t *stdout_buffer,
    cmaper_scan_process_buffer_t *stderr_buffer,
    int *wait_status
) {
    bool child_running = true;
    cmaper_scan_heartbeat_t heartbeat;
    long long now_ms = cmaper_scan_now_ms();

    cmaper_scan_heartbeat_init(&heartbeat, heartbeat_seconds, now_ms);

    while (*stdout_fd >= 0 || *stderr_fd >= 0 || child_running) {
        struct pollfd fds[2];
        nfds_t fds_count = 0;
        int poll_rc;

        if (*stdout_fd >= 0) {
            fds[fds_count].fd = *stdout_fd;
            fds[fds_count].events = POLLIN | POLLHUP | POLLERR;
            fds[fds_count].revents = 0;
            fds_count += 1;
        }

        if (*stderr_fd >= 0) {
            fds[fds_count].fd = *stderr_fd;
            fds[fds_count].events = POLLIN | POLLHUP | POLLERR;
            fds[fds_count].revents = 0;
            fds_count += 1;
        }

        poll_rc = poll(fds, fds_count, 1000);
        if (poll_rc < 0 && errno != EINTR) {
            return CMAPER_ERR_IO;
        }

        if (poll_rc > 0) {
            nfds_t i;
            for (i = 0; i < fds_count; ++i) {
                cmaper_err_t read_rc;

                if ((fds[i].revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
                    continue;
                }

                if (fds[i].fd == *stdout_fd && *stdout_fd >= 0) {
                    read_rc = cmaper_scan_process_read_pipe(stdout_fd, stdout_buffer);
                    if (read_rc != CMAPER_OK) {
                        return read_rc;
                    }
                } else if (fds[i].fd == *stderr_fd && *stderr_fd >= 0) {
                    read_rc = cmaper_scan_process_read_pipe(stderr_fd, stderr_buffer);
                    if (read_rc != CMAPER_OK) {
                        return read_rc;
                    }
                }
            }
        }

        if (child_running) {
            pid_t waited = waitpid(child_pid, wait_status, WNOHANG);
            if (waited < 0) {
                return CMAPER_ERR_IO;
            }
            if (waited == child_pid) {
                child_running = false;
            }
        }

        if (child_running && heartbeat_seconds > 0) {
            long long elapsed_ms = 0;

            now_ms = cmaper_scan_now_ms();
            if (cmaper_scan_heartbeat_should_emit(&heartbeat, now_ms, &elapsed_ms)) {
                const char *label = heartbeat_label != NULL ? heartbeat_label : "scan/process";
                cmaper_log(
                    logger,
                    CMAPER_LOG_WAIT,
                    "%s: still running after %llds",
                    label,
                    elapsed_ms / 1000LL
                );
            }
        }

        if (!child_running && *stdout_fd < 0 && *stderr_fd < 0) {
            break;
        }
    }

    return CMAPER_OK;
}

static void cmaper_scan_process_ensure_waited(pid_t child_pid, int *wait_status) {
    if (child_pid <= 0 || wait_status == NULL) {
        return;
    }

    while (waitpid(child_pid, wait_status, 0) < 0) {
        if (errno != EINTR) {
            break;
        }
    }
}

cmaper_err_t cmaper_scan_process_run(
    const cmaper_scan_process_request_t *request,
    cmaper_logger_t *logger,
    cmaper_scan_process_result_t *result
) {
    int stdout_pipe[2] = { -1, -1 };
    int stderr_pipe[2] = { -1, -1 };
    pid_t child_pid = -1;
    int wait_status = 0;
    cmaper_scan_process_buffer_t stdout_buffer;
    cmaper_scan_process_buffer_t stderr_buffer;
    cmaper_err_t rc = CMAPER_OK;

    if (request == NULL || result == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    if (request->program_path == NULL || request->program_path[0] == '\0' || request->argv == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_scan_process_result_init(result);
    cmaper_scan_process_buffer_init(&stdout_buffer);
    cmaper_scan_process_buffer_init(&stderr_buffer);

    if (pipe(stdout_pipe) != 0) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    if (pipe(stderr_pipe) != 0) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    child_pid = fork();
    if (child_pid < 0) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    if (child_pid == 0) {
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);

        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        close(stderr_pipe[0]);
        close(stderr_pipe[1]);

        execv(request->program_path, (char *const *) request->argv);
        dprintf(STDERR_FILENO, "failed to exec '%s': %s\n", request->program_path, strerror(errno));
        _exit(127);
    }

    cmaper_scan_close_fd(&stdout_pipe[1]);
    cmaper_scan_close_fd(&stderr_pipe[1]);

    rc = cmaper_scan_process_set_nonblocking(stdout_pipe[0]);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    rc = cmaper_scan_process_set_nonblocking(stderr_pipe[0]);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    rc = cmaper_scan_process_wait_loop(
        child_pid,
        &stdout_pipe[0],
        &stderr_pipe[0],
        request->heartbeat_seconds,
        request->heartbeat_label,
        logger,
        &stdout_buffer,
        &stderr_buffer,
        &wait_status
    );
    if (rc != CMAPER_OK) {
        kill(child_pid, SIGKILL);
        cmaper_scan_process_ensure_waited(child_pid, &wait_status);
        child_pid = -1;
        goto cleanup;
    }

    if (WIFEXITED(wait_status)) {
        result->exit_code = WEXITSTATUS(wait_status);
    } else if (WIFSIGNALED(wait_status)) {
        result->exit_code = 128 + WTERMSIG(wait_status);
        result->exited_by_signal = true;
        result->signal_number = WTERMSIG(wait_status);
    } else {
        result->exit_code = 1;
    }

    if (stdout_buffer.data == NULL) {
        stdout_buffer.data = (char *) malloc(1);
        if (stdout_buffer.data == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        stdout_buffer.data[0] = '\0';
    }
    if (stderr_buffer.data == NULL) {
        stderr_buffer.data = (char *) malloc(1);
        if (stderr_buffer.data == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        stderr_buffer.data[0] = '\0';
    }

    result->stdout_data = stdout_buffer.data;
    result->stdout_size = stdout_buffer.size;
    stdout_buffer.data = NULL;
    stdout_buffer.size = 0;
    stdout_buffer.capacity = 0;

    result->stderr_data = stderr_buffer.data;
    result->stderr_size = stderr_buffer.size;
    stderr_buffer.data = NULL;
    stderr_buffer.size = 0;
    stderr_buffer.capacity = 0;

cleanup:
    cmaper_scan_close_fd(&stdout_pipe[0]);
    cmaper_scan_close_fd(&stdout_pipe[1]);
    cmaper_scan_close_fd(&stderr_pipe[0]);
    cmaper_scan_close_fd(&stderr_pipe[1]);

    if (child_pid > 0) {
        cmaper_scan_process_ensure_waited(child_pid, &wait_status);
    }

    cmaper_scan_process_buffer_dispose(&stdout_buffer);
    cmaper_scan_process_buffer_dispose(&stderr_buffer);

    if (rc != CMAPER_OK) {
        cmaper_scan_process_result_dispose(result);
    }

    return rc;
}
