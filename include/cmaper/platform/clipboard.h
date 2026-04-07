#ifndef CMAPER_PLATFORM_CLIPBOARD_H
#define CMAPER_PLATFORM_CLIPBOARD_H

#include <stddef.h>

#include "cmaper/core/error.h"

cmaper_err_t cmaper_platform_clipboard_copy(const char *data, size_t data_size);

#endif
