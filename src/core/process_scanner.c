/**
 * @file process_scanner.c
 * @brief Core process scanning using kvm_getprocs()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <kvm.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/pledge.h>

#include "process_core.h"
#include "pledge_analyzer.h"
#include "wx_monitor.h"
#include "opensec.h"
#include "logger.h"

/* OpenBSD process flags - from sys/proc.h */
#ifndef P_CHROOT
#define P_CHROOT       0x01000000
#endif

#ifndef P_WXNEEDED
#define P_WXNEEDED     0x02000000
#endif

#ifndef P_SYSTEM
#define P_SYSTEM       0x00002000
#endif

/* ========================================================= */
/*                PROCESS COLLECTION                         */
/* ========================================================= */

/**
 * @brief Get all processes using kvm interface
 */
ProcessInfo *get_all_processes(int *count)
{
    kvm_t *kd;
    struct kinfo_proc *procs;
    int nprocs;
    ProcessInfo *result;

    kd = kvm_open(NULL, NULL, NULL, KVM_NO_FILES, "kvm_open");
    if (kd == NULL) {
        log_error("Cannot open kvm interface");
        return NULL;
    }

    procs = kvm_getprocs(kd, KERN_PROC_KTHREAD, 0,
                         sizeof(*procs), &nprocs);
    if (procs == NULL || nprocs == 0) {
        log_error("Cannot get process list");
        kvm_close(kd);
        return NULL;
    }

    result = calloc(nprocs, sizeof(ProcessInfo));
    if (result == NULL) {
        kvm_close(kd);
        return NULL;
    }

    for (int i = 0; i < nprocs; i++) {
        result[i].pid = procs[i].p_pid;
        result[i].tid = procs[i].p_tid;

        strlcpy(result[i].name,
                procs[i].p_comm,
                sizeof(result[i].name));

        result[i].flags      = procs[i].p_flag;
        result[i].is_system  = (procs[i].p_flag & P_SYSTEM) != 0;
        result[i].chrooted   = (procs[i].p_flag & P_CHROOT) != 0;
        result[i].wxneeded   = (procs[i].p_flag & P_WXNEEDED) != 0;
        result[i].is_thread  = (procs[i].p_tid != -1);

        result[i].has_pledge = 0;
        /* NÃO inicializar pledges - quem faz isso é o pledge_analyzer */
        result[i].command[0] = '\0';
        result[i].has_unveil = 0;
        result[i].wxviolation = 0;
    }

    *count = nprocs;
    kvm_close(kd);
    return result;
}

/* ========================================================= */
/*                PROCESS COMMAND LINE                       */
/* ========================================================= */

/**
 * @brief Get full command line for a process
 */
int get_process_command(pid_t pid, char *buffer, size_t buflen)
{
    int mib[4];
    size_t len;
    char *args;

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC_ARGS;
    mib[2] = pid;
    mib[3] = KERN_PROC_ARGV;

    if (sysctl(mib, 4, NULL, &len, NULL, 0) == -1) {
        strlcpy(buffer, "unknown", buflen);
        return -1;
    }

    args = malloc(len);
    if (args == NULL) {
        strlcpy(buffer, "unknown", buflen);
        return -1;
    }

    if (sysctl(mib, 4, args, &len, NULL, 0) == -1) {
        free(args);
        strlcpy(buffer, "unknown", buflen);
        return -1;
    }

    strlcpy(buffer, args, buflen);
    free(args);
    return 0;
}

/* ========================================================= */
/*                MAIN SCAN                                  */
/* ========================================================= */

/**
 * @brief Main scanning function
 */
int scan_all_processes(SystemStats *stats)
{
    int count;
    ProcessInfo *processes = get_all_processes(&count);

    if (processes == NULL)
        return -1;

    for (int i = 0; i < count; i++) {
        get_process_pledges(&processes[i]);
        get_process_command(processes[i].pid,
                            processes[i].command,
                            sizeof(processes[i].command));
        check_wx_status(&processes[i]);
    }

    if (stats != NULL) {
        memset(stats, 0, sizeof(SystemStats));
        stats->total_processes = count;

        for (int i = 0; i < count; i++) {
            if (processes[i].is_thread)
                stats->total_threads++;

            if (processes[i].has_pledge)
                stats->pledged_processes++;

            if (processes[i].wxneeded)
                stats->wxneeded_processes++;

            if (processes[i].chrooted)
                stats->chrooted_processes++;

            if (processes[i].is_system)
                stats->system_processes++;
        }
    }

    /* A função print_process_table agora é chamada em main.c */
    free(processes);

    return count;
}
