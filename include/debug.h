#pragma once

#include <stdbool.h>
#include <stdio.h>

/* Optional debugging settings, specified at runtime */
extern bool Debug;
extern bool DebugExtra;

extern bool ShowHigh;
extern bool ShowMed;
extern bool ShowLow;
extern bool ShowInfo;

/* This function will only be executed if the runtime argument */
/* -d 1 or -d 2 is passed */
#define DEBUG_PRINT(fmt, ...)                             \
    do                                                    \
    {                                                     \
        if (Debug)                                        \
            fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                    __LINE__, __func__, __VA_ARGS__);     \
    } while (0)

/* This function will only be executed if the runtime argument */
/* -d 2 is passed */
#define DEBUG_PRINT_EXTRA(fmt, ...)                                     \
    do                                                                  \
    {                                                                   \
        if (DebugExtra)                                                 \
            fprintf(stderr, "debug extra-> %s:%d:%s(): " fmt, __FILE__, \
                    __LINE__, __func__, __VA_ARGS__);                   \
    } while (0)

bool set_print_lvl_greater_than(char *s);

bool set_disable_print_level(char *s);