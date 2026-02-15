#ifndef LOGGER_H
#define LOGGER_H

/**
 * @file logger.h
 * @brief Logging utilities for OpenSec
 */

/**
 * @brief Log informational message
 * @param format printf-style format string
 */
void log_info(const char *format, ...);

/**
 * @brief Log error message (red text)
 * @param format printf-style format string
 */
void log_error(const char *format, ...);

/**
 * @brief Log debug message (yellow text)
 * @param format printf-style format string
 */
void log_debug(const char *format, ...);

#endif // LOGGER_H
