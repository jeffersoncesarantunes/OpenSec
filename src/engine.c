#include "opensec.h"
#include <fcntl.h>
#include <limits.h>
#include <sys/proc.h>

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
        strncpy(list[i].name, kp[i].p_comm, sizeof(list[i].name));

        if (kp[i].p_psflags & PS_PLEDGE) 
            list[i].has_pledge = 1;
        
        /* 0x1000000 is the internal kernel flag for active unveil(2) */
        if (kp[i].p_psflags & 0x1000000) 
            list[i].has_unveil = 1;

        if (kp[i].p_psflags & PS_WXNEEDED) 
            list[i].wxneeded = 1;

        if (kp[i].p_flag & P_CHROOT) 
            list[i].chrooted = 1;
    }

    *count = nprocs;
    kvm_close(kd);
    return list;
}
