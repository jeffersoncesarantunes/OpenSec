/**
 * @file pledge_analyzer.c
 * @brief OpenBSD pledge(2) analysis - VERSÃO FINAL CORRIGIDA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/pledge.h>
#include "pledge_analyzer.h"
#include "colors.h"
#include "logger.h"
#include "process_core.h"

/* Pledge flags are uint64_t in OpenBSD */
typedef uint64_t pledge_flags_t;

/**
 * @brief Array of pledge flag names for lookup
 */
typedef struct {
    pledge_flags_t flag;
    const char *name;
} pledge_flag_entry_t;

static const pledge_flag_entry_t pledge_flags[] = {
    { PLEDGE_STDIO,  "stdio" },
    { PLEDGE_RPATH,  "rpath" },
    { PLEDGE_WPATH,  "wpath" },
    { PLEDGE_CPATH,  "cpath" },
    { PLEDGE_DPATH,  "dpath" },
    { PLEDGE_TMPPATH, "tmppath" },
    { PLEDGE_INET,   "inet" },
    { PLEDGE_MCAST,  "mcast" },
    { PLEDGE_UNIX,   "unix" },
    { PLEDGE_DNS,    "dns" },
    { PLEDGE_GETPW,  "getpw" },
    { PLEDGE_SENDFD, "sendfd" },
    { PLEDGE_RECVFD, "recvfd" },
#ifdef PLEDGE_TAINT
    { PLEDGE_TAINT,  "taint" },
#endif
    { PLEDGE_PROC,   "proc" },
    { PLEDGE_EXEC,   "exec" },
    { PLEDGE_FATTR,  "fattr" },
#ifdef PLEDGE_CHOWN
    { PLEDGE_CHOWN,  "chown" },
#endif
    { PLEDGE_VMINFO, "vminfo" },
    { PLEDGE_ID,     "id" },
    { PLEDGE_PF,     "pf" },
    { PLEDGE_ROUTE,  "route" },
#ifdef PLEDGE_WX
    { PLEDGE_WX,     "wx" },
#endif
    { PLEDGE_AUDIO,  "audio" },
#ifdef PLEDGE_VIDEO
    { PLEDGE_VIDEO,  "video" },
#endif
#ifdef PLEDGE_BPF
    { PLEDGE_BPF,    "bpf" },
#endif
#ifdef PLEDGE_UNVEIL
    { PLEDGE_UNVEIL, "unveil" },
#endif
#ifdef PLEDGE_CRYPTO
    { PLEDGE_CRYPTO, "crypto" },
#endif
    { 0, NULL }
};

/**
 * @brief Convert pledge flags to space-separated string
 */
void pledge_flags_to_string(pledge_flags_t pledges, char *buffer, size_t buflen) {
    int first = 1;
    
    buffer[0] = '\0';
    
    for (const pledge_flag_entry_t *entry = pledge_flags; entry->flag != 0; entry++) {
        if (pledges & entry->flag) {
            if (!first) {
                strlcat(buffer, " ", buflen);
            }
            strlcat(buffer, entry->name, buflen);
            first = 0;
        }
    }
    
    if (first) {
        strlcpy(buffer, "none", buflen);
    }
}

/**
 * @brief Get pledge using popen() to run ps - VERSÃO CORRIGIDA
 */
static int get_pledge_from_ps(ProcessInfo *p) {
    char cmd[128];
    char line[256];
    FILE *fp;
    int found = 0;
    
    /* Inicializa como NO PLEDGE */
    p->has_pledge = 0;
    strlcpy(p->pledges, "NO PLEDGE", sizeof(p->pledges));
    
    snprintf(cmd, sizeof(cmd), "ps -o pledge -p %d | tail -1", p->pid);
    fp = popen(cmd, "r");
    if (!fp) return 0;
    
    if (fgets(line, sizeof(line), fp)) {
        char *start = line;
        char *end;
        
        /* Remove espaços e tabs do início */
        while (*start == ' ' || *start == '\t') start++;
        
        /* Remove espaços e newline do final */
        end = start + strlen(start) - 1;
        while (end > start && (*end == ' ' || *end == '\t' || *end == '\n')) {
            *end = '\0';
            end--;
        }
        
        /* Se sobrou algo e NÃO é uma linha vazia */
        if (strlen(start) > 0) {
            /* Verifica se é um pledge real (contém vírgulas ou palavras conhecidas) */
            if (strchr(start, ',') != NULL || 
                strcmp(start, "stdio") == 0 ||
                strstr(start, "rpath") != NULL ||
                strstr(start, "inet") != NULL ||
                strstr(start, "unix") != NULL) {
                
                strlcpy(p->pledges, start, sizeof(p->pledges));
                p->has_pledge = 1;
                found = 1;
            }
        }
    }
    
    pclose(fp);
    return found;
}

/**
 * @brief Get pledge promises for a process
 */
int get_process_pledges(ProcessInfo *p) {
    /* Tenta obter do ps (método que funcionou antes) */
    if (get_pledge_from_ps(p)) {
        return 1;
    }
    
    /* Se não conseguiu, é NO PLEDGE */
    p->has_pledge = 0;
    strlcpy(p->pledges, "NO PLEDGE", sizeof(p->pledges));
    return 0;
}

/**
 * @brief Analyze pledge risk level
 */
int analyze_pledge_risk(const ProcessInfo *p) {
    if (!p->has_pledge) {
        return 3;
    }
    
    int risk = 0;
    
    if (strstr(p->pledges, "exec") && strstr(p->pledges, "proc")) {
        risk = 2;
    }
    
    if (strstr(p->pledges, "wx")) {
        risk = 2;
    }
    
    return risk;
}

/**
 * @brief Print pledge analysis with colors
 */
void print_pledge_info(const ProcessInfo *p) {
    int risk = analyze_pledge_risk(p);
    
    if (!p->has_pledge) {
        printf("%s%-32s%s", COLOR_ERROR, "NO PLEDGE", COLOR_RESET);
    } else if (risk >= 2) {
        printf("%s%-32s%s", COLOR_WARNING, p->pledges, COLOR_RESET);
    } else {
        printf("%-32s", p->pledges);
    }
}

/**
 * @brief Get human-readable pledge risk description
 */
const char *get_pledge_risk_description(int risk) {
    switch (risk) {
        case 0: return "Well-pledged";
        case 1: return "Permissive";
        case 2: return "Contains exec/proc/wx";
        case 3: return "NO PLEDGE";
        default: return "Unknown";
    }
}

/**
 * @brief Check if a specific promise is present
 */
int has_pledge_promise(const ProcessInfo *p, const char *promise) {
    if (!p->has_pledge) return 0;
    return (strstr(p->pledges, promise) != NULL);
}
