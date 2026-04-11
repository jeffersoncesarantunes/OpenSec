#include "opensec.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>
#include <kvm.h>
#include <errno.h>

#define RED    "\x1b[31m"
#define GRN    "\x1b[32m"
#define YEL    "\x1b[33m"
#define BLU    "\x1b[34m"
#define MAG    "\x1b[35m"
#define CYN    "\x1b[36m"
#define BOLD   "\x1b[1m"
#define RESET  "\x1b[0m"

enum OutputFormat { NONE, JSON, CSV };
int quiet_mode = 0;

void print_separator() {
    if (quiet_mode) return;
    printf("-----------------------------------------------------------------------------------------\n");
}

void print_header() {
    if (quiet_mode) return;
    printf(BOLD CYN "=========================================================================================\n");
    printf("  OpenSec - OpenBSD Security Auditor\n");
    printf("=========================================================================================\n" RESET);
}

void export_json_manual(ProcessInfo *processes, int count, const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) return;
    fputs("[\n", f);
    for (int i = 0; i < count; i++) {
        fprintf(f, "  {\n");
        fprintf(f, "    \"pid\": %d,\n", processes[i].pid);
        fprintf(f, "    \"name\": \"%s\",\n", processes[i].name);
        fprintf(f, "    \"pledge\": %s,\n", processes[i].has_pledge ? "true" : "false");
        fprintf(f, "    \"unveil\": %s,\n", processes[i].has_unveil ? "true" : "false");
        fprintf(f, "    \"wxneeded\": %s,\n", processes[i].wxneeded ? "true" : "false");
        fprintf(f, "    \"chrooted\": %s,\n", processes[i].chrooted ? "true" : "false");
        fprintf(f, "    \"context\": \"%s\"\n", (processes[i].pid < 100) ? "KERNEL" : "NATIVE");
        fprintf(f, "  }%s\n", (i + 1 < count) ? "," : "");
    }
    fputs("]\n", f);
    fclose(f);
}

void export_csv(ProcessInfo *processes, int count, const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) return;
    fprintf(f, "pid,name,pledge,unveil,wxneeded,chrooted,context\n");
    for (int i = 0; i < count; i++) {
        fprintf(f, "%d,%s,%d,%d,%d,%d,%s\n",
            processes[i].pid, processes[i].name, processes[i].has_pledge,
            processes[i].has_unveil, processes[i].wxneeded, processes[i].chrooted,
            (processes[i].pid < 100) ? "KERNEL" : "NATIVE"
        );
    }
    fclose(f);
}

int main(int argc, char *argv[]) {
    enum OutputFormat out_format = NONE;
    int target_wx_pid = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0) quiet_mode = 1;
        if (strcmp(argv[i], "--scan-wx") == 0 && i + 1 < argc) target_wx_pid = atoi(argv[++i]);
        if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            if (strcmp(argv[i+1], "json") == 0) out_format = JSON;
            else if (strcmp(argv[i+1], "csv") == 0) out_format = CSV;
        }
    }

    if (target_wx_pid > 0) {
        audit_process_memory(target_wx_pid);
        return 0;
    }

    print_header();
    
    if (!quiet_mode) {
        printf(BOLD CYN "--- Runtime State Audit ---" RESET "\n");
        audit_self();
    }

    int count = 0;
    ProcessInfo *processes = get_all_processes(&count);
    if (!processes) errx(1, "Could not fetch process list");

    unveil("/dev", "r");
    unveil("output.json", "rwc");
    unveil("output.csv", "rwc");
    unveil("/usr/lib", "r");
    unveil(NULL, NULL);

    if (pledge("stdio rpath wpath cpath ps vminfo", NULL) == -1) err(1, "pledge");

    if (!quiet_mode) {
        printf("\n" BOLD "[+] Scanning system processes...\n\n" RESET);
        printf(BOLD "%-8s %-25s %-15s %-15s %-10s\n" RESET, "PID", "PROCESS", "PLEDGE", "UNVEIL", "CONTEXT");
        print_separator();
    }

    int pledged_count = 0, chroot_count = 0, wx_count = 0;

    for (int i = 0; i < count; i++) {
        if (processes[i].has_pledge) pledged_count++;
        if (processes[i].chrooted) chroot_count++;
        if (processes[i].wxneeded) wx_count++;

        if (!quiet_mode) {
            char *ctx_label = (processes[i].pid < 100) ? "KERNEL" : "NATIVE";
            char *ctx_color = (processes[i].pid < 100) ? MAG : BLU;
            printf("%-8d %-25.25s ", processes[i].pid, processes[i].name);
            printf("%s%-15s" RESET " ", processes[i].has_pledge ? GRN : RED, processes[i].has_pledge ? "ACTIVE" : "NONE");
            printf("%s%-15s" RESET " ", processes[i].has_unveil ? GRN : YEL, processes[i].has_unveil ? "ACTIVE" : "NONE");
            printf("%s%-10s" RESET "\n", ctx_color, ctx_label);

            if ((i + 1) % 20 == 0 && (i + 1) < count) {
                printf("\n" BOLD YEL "[PAUSED] Press ENTER to continue (%d/%d)..." RESET "\n", i + 1, count);
                getchar();
            }
        }
    }

    if (!quiet_mode) {
        print_separator();
        printf("\n" BOLD "[+] MITIGATION SUMMARY\n" RESET);
        printf("    [#] Total Processes: %d\n", count);
        printf("    [#] Pledge Status:   %d (%.1f%%)\n", pledged_count, (float)pledged_count/count*100);
        printf("    [#] Memory Audit:    " GRN "HARDENED" RESET " (%d processes with WXNEEDED)\n", wx_count);
        printf("    [#] Chroot Jails:    %d processes\n", chroot_count);
        printf("\n" BOLD GRN "[*] Audit complete." RESET "\n");
    }

    if (out_format == JSON) export_json_manual(processes, count, "output.json");
    if (out_format == CSV) export_csv(processes, count, "output.csv");

    free(processes);
    return 0;
}
