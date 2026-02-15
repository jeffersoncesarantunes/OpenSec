#ifndef PROCESS_CORE_H
#define PROCESS_CORE_H

/**
 * @file process_core.h
 * @brief Core process structures for OpenBSD
 * 
 * Includes all necessary OpenBSD headers for process structures.
 */

#include <sys/param.h>      /* Para constants */
#include <sys/types.h>      /* Tipos básicos */
#include <sys/sysctl.h>     /* Sysctl interface */
#include <sys/proc.h>        /* Process structures */
#include <sys/signal.h>      /* Para struct sigaltstack */
#include <sys/siginfo.h>     /* Para union sigval */
#include <sys/time.h>        /* Para struct timeval */
#include <sys/resource.h>    /* Para resource limits */
#include <sys/pledge.h>      /* Para pledge constants */
#include <sys/ucred.h>       /* Para struct ucred */
#include <sys/mount.h>       /* Para struct statfs */
#include <sys/vnode.h>       /* Para vnode structures */
#include <sys/filedesc.h>    /* Para file descriptors */
#include <sys/namei.h>       /* Para namei structures */
#include <sys/unistd.h>      /* Para constantes */
#include <kvm.h>             /* Para kvm interface */

/**
 * @brief Process security information structure
 */
typedef struct {
    pid_t pid;              /**< Process ID */
    pid_t tid;              /**< Thread ID (-1 for main process) */
    char name[256];         /**< Process name (p_comm) */
    char command[1024];     /**< Full command line */
    
    /* Pledge information */
    int has_pledge;         /**< Whether process uses pledge(2) */
    char pledges[512];      /**< Human-readable pledge promises */
    
    /* W^X information */
    int wxneeded;           /**< PS_WXNEEDED flag */
    int wxviolation;        /**< Detected W^X violation */
    
    /* Isolation information */
    int chrooted;           /**< PS_CHROOT flag */
    int has_unveil;         /**< Whether process uses unveil(2) */
    
    /* Process state */
    int is_thread;          /**< 1 if this is a thread, 0 if main process */
    int is_system;          /**< PS_SYSTEM flag (kernel thread) */
    
    /* Additional flags */
    int flags;              /**< Raw p_flag values */
} ProcessInfo;

/**
 * @brief System security status
 */
typedef struct {
    int total_processes;    /**< Total number of processes */
    int total_threads;      /**< Total number of threads */
    int pledged_processes;  /**< Processes using pledge */
    int wxneeded_processes; /**< Processes requiring W^X */
    int chrooted_processes; /**< Chrooted processes */
    int system_processes;   /**< Kernel threads */
} SystemStats;

#endif // PROCESS_CORE_H
