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

static const char *score_color(int score) {
    if (score >= 4) return GRN;
    if (score >= 1) return YEL;
    return RED;
}

void print_separator(void) {
    if (quiet_mode) return;
    printf("----------------------------------------------------------------------------------------------------\n");
}

void print_header(void) {
    if (quiet_mode) return;
    printf(BOLD CYN "==========================================================================================\n");
    printf("  OpenSec - OpenBSD Security Auditor\n");
    printf("==========================================================================================\n" RESET);
}

void export_json_manual(ProcessInfo *processes, int count, const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) return;
    fputs("[\n", f);
    for (int i = 0; i < count; i++) {
        fprintf(f, "  {\n");
        fprintf(f, "    \"pid\": %d,\n", processes[i].pid);
        fprintf(f, "    \"ppid\": %d,\n", processes[i].ppid);
        fprintf(f, "    \"name\": \"%s\",\n", processes[i].name);
        fprintf(f, "    \"ppname\": \"%s\",\n", processes[i].ppname);
        fprintf(f, "    \"pledge\": %s,\n", processes[i].has_pledge ? "true" : "false");
        fprintf(f, "    \"unveil\": %s,\n", processes[i].has_unveil ? "true" : "false");
        fprintf(f, "    \"wxneeded\": %s,\n", processes[i].wxneeded ? "true" : "false");
        fprintf(f, "    \"chrooted\": %s,\n", processes[i].chrooted ? "true" : "false");
        fprintf(f, "    \"context\": \"%s\",\n", (processes[i].pid < 100) ? "KERNEL" : "NATIVE");
        fprintf(f, "    \"score\": %d\n", processes[i].score);
        fprintf(f, "  }%s\n", (i + 1 < count) ? "," : "");
    }
    fputs("]\n", f);
    fclose(f);
}

void export_csv(ProcessInfo *processes, int count, const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) return;
    fprintf(f, "pid,ppid,name,ppname,pledge,unveil,wxneeded,chrooted,context,score\n");
    for (int i = 0; i < count; i++) {
        fprintf(f, "%d,%d,%s,%s,%d,%d,%d,%d,%s,%d\n",
            processes[i].pid, processes[i].ppid, processes[i].name, processes[i].ppname,
            processes[i].has_pledge, processes[i].has_unveil,
            processes[i].wxneeded, processes[i].chrooted,
            (processes[i].pid < 100) ? "KERNEL" : "NATIVE",
            processes[i].score
        );
    }
    fclose(f);
}

int main(int argc, char *argv[]) {
    enum OutputFormat out_format = NONE;
    int target_wx_pid = 0;
    pid_t target_pid = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0)
            quiet_mode = 1;
        else if (strcmp(argv[i], "--scan-wx") == 0 && i + 1 < argc)
            target_wx_pid = atoi(argv[++i]);
        else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc)
            target_pid = (pid_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            if (strcmp(argv[i+1], "json") == 0) out_format = JSON;
            else if (strcmp(argv[i+1], "csv") == 0) out_format = CSV;
            i++;
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

    int display_count = 0;
    ProcessInfo *display_list = NULL;

    if (target_pid > 0) {
        for (int i = 0; i < count; i++) {
            if (processes[i].pid == target_pid || processes[i].ppid == target_pid)
                display_count++;
        }
        display_list = calloc(display_count, sizeof(ProcessInfo));
        if (!display_list) errx(1, "calloc");
        int idx = 0;
        for (int i = 0; i < count; i++) {
            if (processes[i].pid == target_pid || processes[i].ppid == target_pid)
                display_list[idx++] = processes[i];
        }
    } else {
        display_count = count;
        display_list = processes;
    }

    unveil("/dev", "r");
    unveil("output.json", "rwc");
    unveil("output.csv", "rwc");
    unveil("/usr/lib", "r");
    unveil(NULL, NULL);

    if (pledge("stdio rpath wpath cpath ps vminfo", NULL) == -1) err(1, "pledge");

    if (!quiet_mode) {
        if (target_pid > 0)
            printf("\n" BOLD "[+] Filtered view for PID %d (including children)\n" RESET, target_pid);
        printf("\n" BOLD "%-8s %-6s %-22s %-22s %-7s %-7s %-7s %-6s\n" RESET,
               "PID", "PPID", "PROCESS", "PARENT", "PLEDGE", "UNVEIL", "W^X", "SCORE");
        print_separator();
    }

    int pledged_count = 0, unveiled_count = 0, chroot_count = 0, wx_count = 0;
    int score_sum = 0, score_max = -999, score_min = 999;

    for (int i = 0; i < display_count; i++) {
        ProcessInfo *p = &display_list[i];
        if (p->has_pledge) pledged_count++;
        if (p->has_unveil) unveiled_count++;
        if (p->chrooted) chroot_count++;
        if (p->wxneeded) wx_count++;
        score_sum += p->score;
        if (p->score > score_max) score_max = p->score;
        if (p->score < score_min) score_min = p->score;

        if (!quiet_mode) {
            char *ctx_color = (p->pid < 100) ? MAG : BLU;
            printf("%s%-8d" RESET " %-6d %-22.22s %-22.22s ",
                   ctx_color, p->pid, p->ppid, p->name, p->ppname);
            printf("%s%-7s" RESET " ", p->has_pledge ? GRN : RED, p->has_pledge ? "ACTIVE" : "NONE");
            printf("%s%-7s" RESET " ", p->has_unveil ? GRN : YEL, p->has_unveil ? "ACTIVE" : "NONE");
            printf("%s%-7s" RESET " ", p->wxneeded ? RED : GRN, p->wxneeded ? "W^X" : "ok");
            printf("%s%-6d" RESET "\n", score_color(p->score), p->score);

            if ((i + 1) % 20 == 0 && (i + 1) < display_count) {
                printf("\n" BOLD YEL "[PAUSED] Press ENTER to continue (%d/%d)..." RESET "\n", i + 1, display_count);
                getchar();
            }
        }
    }

    if (!quiet_mode) {
        print_separator();
        printf("\n" BOLD "[+] MITIGATION SUMMARY\n" RESET);
        printf("    [#] Total Processes:      %d\n", display_count);
        printf("    [#] Pledge Active:        %d (%.1f%%)\n", pledged_count,
               display_count > 0 ? (float)pledged_count / display_count * 100 : 0);
        printf("    [#] Unveil Active:        %d (%.1f%%)\n", unveiled_count,
               display_count > 0 ? (float)unveiled_count / display_count * 100 : 0);
        printf("    [#] W^X Violations:       %s%d" RESET "\n",
               wx_count > 0 ? RED : GRN, wx_count);
        printf("    [#] Chroot Jails:         %d\n", chroot_count);
        printf("\n" BOLD "[+] SECURITY SCORING\n" RESET);
        printf("    [#] Average Score:        %.1f / 6\n",
               display_count > 0 ? (float)score_sum / display_count : 0);
        printf("    [#] Highest Score:        %s%d" RESET " / 6\n", score_color(score_max), score_max);
        printf("    [#] Lowest Score:         %s%d" RESET " / 6\n", score_color(score_min), score_min);
        printf("\n" BOLD GRN "[*] Audit complete." RESET "\n");
    }

    if (out_format == JSON) export_json_manual(display_list, display_count, "output.json");
    if (out_format == CSV) export_csv(display_list, display_count, "output.csv");

    if (target_pid > 0 && display_list) free(display_list);
    free(processes);
    return 0;
}
