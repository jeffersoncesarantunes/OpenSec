#include "opensec.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>

#define RED   "\x1b[31m"
#define GRN   "\x1b[32m"
#define YEL   "\x1b[33m"
#define BLU   "\x1b[34m"
#define MAG   "\x1b[35m"
#define CYN   "\x1b[36m"
#define BOLD  "\x1b[1m"
#define RESET "\x1b[0m"

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
    printf(BOLD "[+] Scanning system processes...\n\n" RESET);
    printf(BOLD "%-8s %-25s %-15s %-15s %-10s\n" RESET, "PID", "PROCESS", "PLEDGE", "UNVEIL", "CONTEXT");
    print_separator();
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
            processes[i].pid,
            processes[i].name,
            processes[i].has_pledge,
            processes[i].has_unveil,
            processes[i].wxneeded,
            processes[i].chrooted,
            (processes[i].pid < 100) ? "KERNEL" : "NATIVE"
        );
    }
    fclose(f);
}

void check_integrity() {
    FILE *f = fopen("baseline.json", "r");
    if (!f) {
        if (!quiet_mode) printf("[!] baseline.json not found\n");
        return;
    }

    char line[512];
    char path[256];
    char expected[128];

    if (!quiet_mode) printf("[+] Checking binary integrity...\n\n");

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, " \"%255[^\"]\" : \"%127[^\"]\"", path, expected) == 2) {
            if (access(path, F_OK) != 0) {
                if (!quiet_mode) printf(RED "[ALERT] %s missing!\n" RESET, path);
                continue;
            }

            char cmd[512];
            snprintf(cmd, sizeof(cmd), "sha256 %s", path);

            FILE *fp = popen(cmd, "r");
            if (!fp) {
                if (!quiet_mode) printf(YEL "[WARN] Could not check %s\n" RESET, path);
                continue;
            }

            char output[256];
            char current[128] = {0};

            if (fgets(output, sizeof(output), fp)) {
                sscanf(output, "SHA256 (%*[^)]) = %127s", current);
            }
            pclose(fp);

            if (strlen(current) == 0) {
                if (!quiet_mode) printf(YEL "[WARN] Failed to read hash for %s\n" RESET, path);
                continue;
            }

            if (strcmp(current, expected) == 0) {
                if (!quiet_mode) printf(GRN "[OK] %s\n" RESET, path);
            } else {
                if (!quiet_mode) {
                    printf(RED "[ALERT] %s modified!\n" RESET, path);
                    printf(RED "        Expected: %s\n" RESET, expected);
                    printf(RED "        Found:    %s\n\n" RESET, current);
                }
            }
        }
    }
    fclose(f);
}

int main(int argc, char *argv[]) {
    enum OutputFormat out_format = NONE;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0) {
            quiet_mode = 1;
        }
    }

    if (unveil("/dev", "r") == -1) err(1, "unveil /dev");
    if (unveil("baseline.json", "r") == -1) err(1, "unveil baseline.json");
    if (unveil("output.json", "rwc") == -1) err(1, "unveil output.json");
    if (unveil("output.csv", "rwc") == -1) err(1, "unveil output.csv");
    if (unveil("/usr/bin/sha256", "rx") == -1) err(1, "unveil /usr/bin/sha256");
    if (unveil(NULL, NULL) == -1) err(1, "unveil lock");

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--check-integrity") == 0) {
            if (pledge("stdio rpath proc exec", NULL) == -1) err(1, "pledge");
            if (!quiet_mode) printf("[+] Running integrity check...\n\n");
            check_integrity();
            return 0;
        }
        if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            if (strcmp(argv[i+1], "json") == 0) out_format = JSON;
            else if (strcmp(argv[i+1], "csv") == 0) out_format = CSV;
            else {
                fprintf(stderr, RED "[!] Unknown format: %s\n" RESET, argv[i+1]);
                return 1;
            }
            i++;
        }
    }

    SystemStats stats = {0};
    int count = 0;
    ProcessInfo *processes = get_all_processes(&count);
    if (!processes) {
        fprintf(stderr, RED BOLD "[!] Error: Could not access KVM. Are you root?\n" RESET);
        return 1;
    }

    if (pledge("stdio rpath wpath cpath ps", NULL) == -1) err(1, "pledge");

    print_header();

    for (int i = 0; i < count; i++) {
        if (processes[i].has_pledge) stats.pledged_processes++;
        if (processes[i].has_unveil) stats.unveiled_processes++;
        if (processes[i].wxneeded) stats.wxneeded_processes++;
        if (processes[i].chrooted) stats.chrooted_processes++;

        if (!quiet_mode) {
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
    }

    if (!quiet_mode) {
        print_separator();
        printf("\n" BOLD "[+] SECURITY SUMMARY\n" RESET);
        printf("    [#] Total Processes: %d\n", count);
        printf("    [#] Pledge Status:   %s%d (%.1f%%)" RESET "\n", GRN, stats.pledged_processes, (float)stats.pledged_processes / (count ? count : 1) * 100);
        printf("    [#] W^X Status:      %s%s" RESET "\n", stats.wxneeded_processes ? RED BOLD "INSECURE" : GRN "ENFORCED", stats.wxneeded_processes ? "" : "");
        printf("    [#] Chroot Jails:    %s%d processes" RESET "\n", CYN, stats.chrooted_processes);
        printf("\n" BOLD GRN "[*] Audit complete." RESET "\n");
    }

    if (out_format == JSON) {
        export_json_manual(processes, count, "output.json");
        if (!quiet_mode) printf(GRN "[*] JSON export completed: output.json\n" RESET);
    } else if (out_format == CSV) {
        export_csv(processes, count, "output.csv");
        if (!quiet_mode) printf(GRN "[*] CSV export completed: output.csv\n" RESET);
    }

    free(processes);
    return 0;
}
