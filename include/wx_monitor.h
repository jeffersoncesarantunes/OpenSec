#ifndef WX_MONITOR_H
#define WX_MONITOR_H

/**
 * @file wx_monitor.h
 * @brief W^X (Write XOR eXecute) monitoring
 */

#include "process_core.h"

/**
 * @brief Check W^X status for a process
 * @param p Process information to fill
 * @return 1 if WXNEEDED, 2 if violation, 0 if compliant
 */
int check_wx_status(ProcessInfo *p);

/**
 * @brief Get detailed W^X information
 * @param pid Process ID
 * @param buffer Output buffer
 * @param buflen Buffer length
 * @return 0 on success, -1 on error
 */
int get_wx_violation_details(pid_t pid, char *buffer, size_t buflen);

/**
 * @brief Print W^X status with colors
 * @param p Process information
 */
void print_wx_status(const ProcessInfo *p);

#endif // WX_MONITOR_H
