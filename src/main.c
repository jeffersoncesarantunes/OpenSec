#include "opensec.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#define RED   "\x1b[31m"
#define GRN   "\x1b[32m"
#define YEL   "\x1b[33m"
#define BLU   "\x1b[34m"
#define MAG   "\x1b[35m"
#define CYN   "\x1b[36m"
#define BOLD  "\x1b[1m"
#define RESET "\x1b[0m"

void print_separator() {
    printf("-----------------------------------------------------------------------------------------\n");
}

void print_header() {
    printf(BOLD CYN "=========================================================================================\n");
    printf("  OpenSec - OpenBSD Process Security Auditor                         [OpenBSD]\n");
    printf("=========================================================================================\n" RESET);
    printf(BOLD "[+] Scanning system processes...\n\n" RESET);
    printf(BOLD "%-8s %-25s %-15s %-15s %-10s\n" RESET, "PID", "PROCESS", "PLEDGE", "UNVEIL", "CONTEXT");
    print_separator();
}

int main() {
    SystemStats stats = {0};
    int count = 0;
    ProcessInfo *processes = get_all_processes(&count);

    if (!processes) {
        fprintf(stderr, RED BOLD "[!] Error: Could not access KVM. Are you root?\n" RESET);
        return 1;
    }

    print_header();

    for (int i = 0; i < count; i++) {
        if (processes[i].has_pledge) stats.pledged_processes++;
        if (processes[i].has_unveil) stats.unveiled_processes++;
        if (processes[i].wxneeded) stats.wxneeded_processes++;
        if (processes[i].chrooted) stats.chrooted_processes++;

        char *ctx_label = (processes[i].pid < 100) ? "KERNEL" : "NATIVE";
        char *ctx_color = (processes[i].pid < 100) ? MAG : BLU;

        printf("%-8d %-25.25s ", processes[i].pid, processes[i].name);
        
        printf("%s%-15s" RESET " ", 
               processes[i].has_pledge ? GRN : RED, 
               processes[i].has_pledge ? "ACTIVE" : "NONE");
        
        printf("%s%-15s" RESET " ", 
               processes[i].has_unveil ? GRN : YEL, 
               processes[i].has_unveil ? "ACTIVE" : "NONE");
        
        printf("%s%-10s" RESET "\n", ctx_color, ctx_label);

        if ((i + 1) % 20 == 0 && (i + 1) < count) {
            print_separator();
            printf("\n" BOLD YEL "[PAUSED] Press ENTER to continue (%d/%d)..." RESET "\n\n", i + 1, count);
            getchar();
            printf(BOLD "%-8s %-25s %-15s %-15s %-10s\n" RESET, "PID", "PROCESS", "PLEDGE", "UNVEIL", "CONTEXT");
            print_separator();
        }
    }

    print_separator();
    printf("\n" BOLD "[+] SECURITY SUMMARY\n" RESET);
    printf("    [#] Total Processes: %d\n", count);
    printf("    [#] Pledge Status:   %s%d (%.1f%%)" RESET "\n", GRN, stats.pledged_processes, (float)stats.pledged_processes / (count ? count : 1) * 100);
    printf("    [#] W^X Status:      %s%s" RESET "\n", stats.wxneeded_processes ? RED BOLD "INSECURE" : GRN "ENFORCED", stats.wxneeded_processes ? "" : "");
    printf("    [#] Chroot Jails:    %s%d processes" RESET "\n", CYN, stats.chrooted_processes);
    printf("\n" BOLD GRN "[*] Audit complete." RESET "\n");

    free(processes);
    return 0;
}
