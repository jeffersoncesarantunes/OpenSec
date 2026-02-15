#ifndef SYSCTL_HARDENING_H
#define SYSCTL_HARDENING_H

/**
 * @file sysctl_hardening.h
 * @brief OpenBSD sysctl security auditing
 */

/**
 * @brief Security check result
 */
typedef struct {
    const char *name;       /**< sysctl name */
    int current_value;      /**< Current value */
    int secure_value;       /**< Recommended secure value */
    int is_secure;          /**< 1 if secure, 0 if insecure */
    const char *description;/**< What this controls */
} SysctlCheck;

/**
 * @brief Run complete sysctl security audit
 * @return Number of insecure settings found
 */
int audit_sysctl_security(void);

/**
 * @brief Print sysctl audit results in table format
 */
void print_sysctl_audit(void);

/**
 * @brief Check individual sysctl for security
 * @param name sysctl name
 * @param expected Expected secure value
 * @return 1 if secure, 0 if insecure
 */
int check_sysctl_secure(const char *name, int expected);

#endif // SYSCTL_HARDENING_H
