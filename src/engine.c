#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/mman.h>
#include <kvm.h>
#include <fcntl.h>
#include <errno.h>
#include "opensec.h"

#ifndef PS_WXNEEDED
#define PS_WXNEEDED 0x00040000
#endif

#ifndef P_CHROOT
#define P_CHROOT 0x00004000
#endif

ProcessInfo* get_all_processes(int *count) {
    kvm_t *kd;
    char errbuf[_POSIX2_LINE_MAX];
    struct kinfo_proc *kp;
    int nprocs;

    kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, errbuf);
    if (kd == NULL) return NULL;

    kp = kvm_getprocs(kd, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc), &nprocs);
    if (kp == NULL) {
        kvm_close(kd);
        return NULL;
    }

    ProcessInfo *list = calloc(nprocs, sizeof(ProcessInfo));
    if (!list) {
        kvm_close(kd);
        return NULL;
    }

    for (int i = 0; i < nprocs; i++) {
        list[i].pid = kp[i].p_pid;
        list[i].ppid = kp[i].p_ppid;
        strncpy(list[i].name, kp[i].p_comm, sizeof(list[i].name));
        list[i].has_pledge = (kp[i].p_psflags & PS_PLEDGE) ? 1 : 0;
        list[i].has_unveil = (kp[i].p_psflags & 0x1000000) ? 1 : 0;
        list[i].wxneeded = (kp[i].p_psflags & PS_WXNEEDED) ? 1 : 0;
        list[i].chrooted = (kp[i].p_flag & P_CHROOT) ? 1 : 0;
    }

    /* Second pass: resolve parent process names */
    for (int i = 0; i < nprocs; i++) {
        list[i].ppname[0] = '\0';
        for (int j = 0; j < nprocs; j++) {
            if (list[j].pid == list[i].ppid) {
                strncpy(list[i].ppname, list[j].name, sizeof(list[i].ppname));
                break;
            }
        }
        if (list[i].ppname[0] == '\0')
            snprintf(list[i].ppname, sizeof(list[i].ppname), "(kernel/init)");
    }

    /* Third pass: compute security scores */
    for (int i = 0; i < nprocs; i++)
        list[i].score = compute_security_score(&list[i]);

    *count = nprocs;
    kvm_close(kd);
    return list;
}

int compute_security_score(const ProcessInfo *p) {
    int score = 0;

    /* pledge(2) is the strongest mitigation on OpenBSD */
    if (p->has_pledge) score += 3;

    /* unveil(2) restricts filesystem visibility */
    if (p->has_unveil) score += 2;

    /* chroot adds an extra containment layer */
    if (p->chrooted)   score += 1;

    /* W^X violations (WXNEEDED) reduce score */
    if (p->wxneeded)   score -= 2;

    return score;
}

void audit_process_memory(int pid) {
    int mib[3];
    struct kinfo_vmentry *vme = NULL;
    size_t size;
    int i, nentries;

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC_VMMAP;
    mib[2] = pid;

    if (sysctl(mib, 3, NULL, &size, NULL, 0) == -1) {
        if (errno == EINVAL) {
            printf("\n" "\x1b[33m" "[!] VMMAP Access Denied: Kernel hardening is active for PID %d." "\x1b[0m" "\n", pid);
            printf("    (ASLR protection prevents memory map inspection via sysctl)\n");
        } else {
            fprintf(stderr, "[-] Kernel error for PID %d: %s\n", pid, strerror(errno));
        }
        return;
    }

    size += sizeof(struct kinfo_vmentry) * 10;
    vme = malloc(size);
    if (!vme) return;

    if (sysctl(mib, 3, vme, &size, NULL, 0) == -1) {
        free(vme);
        return;
    }

    nentries = size / sizeof(struct kinfo_vmentry);

    printf("\n[+] Fine-grained W^X Audit for PID %d\n", pid);
    printf("    %-18s %-18s %-10s\n", "START ADDR", "END ADDR", "PROTECTION");

    for (i = 0; i < nentries; i++) {
        if (vme[i].kve_start == 0 && vme[i].kve_end == 0) continue;

        char prot_str[4] = "---";
        if (vme[i].kve_protection & PROT_READ)  prot_str[0] = 'r';
        if (vme[i].kve_protection & PROT_WRITE) prot_str[1] = 'w';
        if (vme[i].kve_protection & PROT_EXEC)  prot_str[2] = 'x';

        if ((vme[i].kve_protection & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)) {
            printf("    0x%016llx-0x%016llx \033[31m%s [VIOLATION]\033[0m\n", 
                   (unsigned long long)vme[i].kve_start, 
                   (unsigned long long)vme[i].kve_end, 
                   prot_str);
        } else {
            printf("    0x%016llx-0x%016llx %s\n", 
                   (unsigned long long)vme[i].kve_start, 
                   (unsigned long long)vme[i].kve_end, 
                   prot_str);
        }
    }

    free(vme);
}

void audit_self(void) {
    audit_process_memory(getpid());
}
