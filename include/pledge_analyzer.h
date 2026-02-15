#ifndef PLEDGE_ANALYZER_H
#define PLEDGE_ANALYZER_H

/**
 * @file pledge_analyzer.h
 * @brief OpenBSD pledge(2) analysis
 */

#include "process_core.h"
#include <sys/pledge.h>
#include <stdint.h>

/* Pledge flags are 64-bit in OpenBSD */
typedef uint64_t pledge_flags_t;

/**
 * @brief Get pledge promises for a process
 * @param p Process structure to fill
 * @return 1 if pledged, 0 if not, -1 on error
 */
int get_process_pledges(ProcessInfo *p);

/**
 * @brief Convert pledge flags to string representation
 * @param pledges Integer flags from kernel (64-bit)
 * @param buffer Output buffer
 * @param buflen Buffer length
 */
void pledge_flags_to_string(pledge_flags_t pledges, char *buffer, size_t buflen);

/**
 * @brief Check if process has dangerous pledge combinations
 * @param p Process information
 * @return Risk level (0-3)
 */
int analyze_pledge_risk(const ProcessInfo *p);

/**
 * @brief Print pledge analysis in colored format
 * @param p Process information
 */
void print_pledge_info(const ProcessInfo *p);

/**
 * @brief Get human-readable pledge risk description
 * @param risk Risk level (0-3)
 * @return String description
 */
const char *get_pledge_risk_description(int risk);

/**
 * @brief Check if a specific promise is present
 * @param p Process information
 * @param promise Promise name (e.g., "stdio", "rpath")
 * @return 1 if present, 0 otherwise
 */
int has_pledge_promise(const ProcessInfo *p, const char *promise);

#endif // PLEDGE_ANALYZER_H
