#ifndef OPENSEC_H
#define OPENSEC_H

#include "colors.h"
#include "process_core.h"
#include "pledge_analyzer.h"
#include "wx_monitor.h"

#define OPENSEC_VERSION "1.0.0"
#define MAX_LINE_LEN 1024
#define DEFAULT_REFRESH 2

/* Banner and usage */
void print_banner(void);
void print_usage(void);

/* Core scanning functions */
ProcessInfo *get_all_processes(int *count);  /* ADICIONADO */
int scan_all_processes(SystemStats *stats);

/* Display functions */
void print_process_table(ProcessInfo *processes, int count);
void truncate_string(const char *src, char *dest, size_t max_len);

/* Memory management */
void free_processes(ProcessInfo *processes, int count);

#endif
