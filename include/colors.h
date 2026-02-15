#ifndef COLORS_H
#define COLORS_H

/**
 * @file colors.h
 * @brief ANSI color codes for terminal output
 */

// Base ANSI color codes
#define CLR_RESET   "\x1b[0m"
#define CLR_RED     "\x1b[31m"
#define CLR_GREEN   "\x1b[32m"
#define CLR_YELLOW  "\x1b[33m"
#define CLR_BLUE    "\x1b[34m"
#define CLR_MAGENTA "\x1b[35m"
#define CLR_CYAN    "\x1b[36m"
#define CLR_BOLD    "\x1b[1m"

// Semantic colors
#define COLOR_RESET     CLR_RESET
#define COLOR_ERROR     CLR_RED
#define COLOR_WARNING   CLR_YELLOW
#define COLOR_GOOD      CLR_GREEN
#define COLOR_INFO      CLR_BLUE
#define COLOR_HIGHLIGHT CLR_CYAN
#define COLOR_BOLD      CLR_BOLD

#endif // COLORS_H
