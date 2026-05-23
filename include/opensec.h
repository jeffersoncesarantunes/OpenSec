#ifndef OPENSEC_H
#define OPENSEC_H

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/mman.h>
#include <kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

typedef struct {
    pid_t pid;
    pid_t ppid;
    char name[64];
    char ppname[64];
    int has_pledge;
    int has_unveil;
    int wxneeded;
    int chrooted;
    int score;
} ProcessInfo;

typedef struct {
    int total;
    int pledged_processes;
    int unveiled_processes;
    int wxneeded_processes;
    int chrooted_processes;
    double avg_score;
    int max_score;
    int min_score;
} SystemStats;

ProcessInfo* get_all_processes(int *count);
int compute_security_score(const ProcessInfo *p);
void audit_process_memory(int pid);
void audit_self(void);

#endif
