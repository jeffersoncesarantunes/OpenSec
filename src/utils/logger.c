/**
 * @file logger.c
 * @brief Logging utilities for OpenSec
 */

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include "logger.h"
#include "colors.h"

void log_info(const char *format, ...) {
    va_list args;
    va_start(args, format);
    printf("[INFO] ");
    vprintf(format, args);
    printf("\n");
    va_end(args);
}

void log_error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    printf("%s[ERROR]%s ", COLOR_ERROR, COLOR_RESET);
    vprintf(format, args);
    printf("\n");
    va_end(args);
}

void log_debug(const char *format, ...) {
    #ifdef DEBUG
    va_list args;
    va_start(args, format);
    printf("%s[DEBUG]%s ", COLOR_WARNING, COLOR_RESET);
    vprintf(format, args);
    printf("\n");
    va_end(args);
    #else
    (void)format;
    #endif
}

void log_warning(const char *format, ...) {
    va_list args;
    va_start(args, format);
    printf("%s[WARNING]%s ", COLOR_WARNING, COLOR_RESET);
    vprintf(format, args);
    printf("\n");
    va_end(args);
}
