#ifndef BSD_UTILS_H
#define BSD_UTILS_H

/**
 * @file bsd_utils.h
 * @brief BSD-specific utility functions
 */

#include <sys/types.h>
#include <sys/sysctl.h>

/**
 * @brief Get system information via sysctl
 * @param name sysctl MIB name
 * @param result Pointer to store result
 * @param size Size of result
 * @return 0 on success, -1 on error
 */
int bsd_sysctl_get(const char *name, void *result, size_t *size);

/**
 * @brief Check if a sysctl value is set to a secure value
 * @param name sysctl name
 * @param expected Expected secure value
 * @return 1 if secure, 0 if insecure, -1 on error
 */
int bsd_check_secure_sysctl(const char *name, int expected);

#endif // BSD_UTILS_H
