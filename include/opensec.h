#ifndef OPENSEC_H
#define OPENSEC_H

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    pid_t pid;
    char name[64];
    int has_pledge;
    int has_unveil;
    int wxneeded;
    int chrooted;
} ProcessInfo;

typedef struct {
    int pledged_processes;
    int unveiled_processes;
    int wxneeded_processes;
    int chrooted_processes;
} SystemStats;

ProcessInfo* get_all_processes(int *count);

#endif
