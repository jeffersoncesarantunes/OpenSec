/**
 * @file main.c
 * @brief OpenSec - Versão final com emojis corrigidos
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "opensec.h"
#include "colors.h"
#include "process_core.h"
#include "pledge_analyzer.h"
#include "wx_monitor.h"

/**
 * @brief Print program banner (alinhado com a tabela)
 */
void print_banner(void) {
    printf("%s", COLOR_BOLD);
    printf("=============================================================================\n");
    printf("                                 OpenSec                                    \n");
    printf("                     OpenBSD Process Security Analyzer                     \n");
    printf("=============================================================================%s\n", COLOR_RESET);
}

/**
 * @brief Print usage information
 */
void print_usage(void) {
    printf("\nUsage: opensec [OPTIONS]\n");
    printf("OpenBSD process security analyzer\n\n");
    printf("Options:\n");
    printf("  -h, --help     Show this help message\n");
    printf("  -v, --version  Show version information\n");
    printf("\n");
}

/**
 * @brief Print process table com alinhamento perfeito
 */
void print_process_table(ProcessInfo *procs, int count) {
    int pledged_count = 0;
    int no_pledge_count = 0;
    
    printf("\n");
    printf("┌────────┬──────────────────────────────┬────────────────────┬──────────────┐\n");
    printf("│ %-6s │ %-28s │ %-18s │ %-12s │\n", 
           "PID", "PROCESS NAME", "PLEDGE STATUS", "CONTEXT");
    printf("├────────┼──────────────────────────────┼────────────────────┼──────────────┤\n");
    
    for (int i = 0; i < count; i++) {
        char context[13];
        const char *color_start = "";
        const char *color_end = "";
        const char *status_text;
        
        /* Determina contexto */
        if (procs[i].wxneeded) {
            strlcpy(context, "JIT", sizeof(context));
        } else if (procs[i].chrooted) {
            strlcpy(context, "CHROOT", sizeof(context));
        } else {
            strlcpy(context, "NATIVE", sizeof(context));
        }
        
        /* Determina status e cor */
        if (!procs[i].has_pledge || 
            strlen(procs[i].pledges) == 0 || 
            strcmp(procs[i].pledges, "NO PLEDGE") == 0) {
            
            status_text = "NO PLEDGE";
            color_start = COLOR_WARNING;
            color_end = COLOR_RESET;
            no_pledge_count++;
        } else {
            status_text = "PLEDGED";
            color_start = "";
            color_end = "";
            pledged_count++;
        }
        
        /* Imprime com cor separada do texto para manter alinhamento */
        printf("│ %-6d │ %-28s │ %s%-18s%s │ %-12s │\n",
               procs[i].pid,
               procs[i].name,
               color_start,
               status_text,
               color_end,
               context);
        
        /* Linha separadora a cada 20 processos */
        if ((i + 1) % 20 == 0 && i < count - 1) {
            printf("├────────┼──────────────────────────────┼────────────────────┼──────────────┤\n");
        }
    }
    
    printf("└────────┴──────────────────────────────┴────────────────────┴──────────────┘\n");
    printf("\n[+] Scan complete. 📊 Total: %d | 🔒 Pledged: %d | ⚠️  No Pledge: %d\n",
           count, pledged_count, no_pledge_count);
}

/**
 * @brief Run complete security audit
 */
int run_audit(void) {
    SystemStats stats;
    int count;
    ProcessInfo *processes;
    
    printf("\n[+] Running complete system security audit...\n");
    
    processes = get_all_processes(&count);
    if (processes == NULL) {
        fprintf(stderr, "Error: Failed to scan processes\n");
        return 1;
    }
    
    for (int i = 0; i < count; i++) {
        get_process_pledges(&processes[i]);
    }
    
    stats.total_processes = count;
    stats.pledged_processes = 0;
    stats.wxneeded_processes = 0;
    stats.chrooted_processes = 0;
    
    for (int i = 0; i < count; i++) {
        if (processes[i].has_pledge) {
            stats.pledged_processes++;
        }
        if (processes[i].wxneeded) stats.wxneeded_processes++;
        if (processes[i].chrooted) stats.chrooted_processes++;
    }
    
    printf("\n[+] System Security Summary:\n");
    printf("    📊 Total processes: %d\n", stats.total_processes);
    printf("    🔒 Pledged processes: %d\n", stats.pledged_processes);
    printf("    ⚠️  WXNEEDED processes: %d\n", stats.wxneeded_processes);
    printf("    🔐 Chrooted processes: %d\n", stats.chrooted_processes);
    
    free(processes);
    return 0;
}

/**
 * @brief Main function
 */
int main(int argc, char *argv[]) {
    ProcessInfo *processes;
    int count;
    int audit_mode = 0;
    
    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_banner();
            print_usage();
            return 0;
        }
        if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
            printf("OpenSec version %s\n", OPENSEC_VERSION);
            return 0;
        }
        if (strcmp(argv[1], "-a") == 0 || strcmp(argv[1], "--audit") == 0) {
            audit_mode = 1;
        }
    }
    
    print_banner();
    
    if (audit_mode) {
        return run_audit();
    }
    
    printf("\n[+] Scanning processes...\n");
    
    processes = get_all_processes(&count);
    if (processes == NULL) {
        fprintf(stderr, "Error: Failed to scan processes\n");
        return 1;
    }
    
    for (int i = 0; i < count; i++) {
        get_process_pledges(&processes[i]);
    }
    
    print_process_table(processes, count);
    
    free(processes);
    return 0;
}
