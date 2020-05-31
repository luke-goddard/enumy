#pragma once

#include <stdbool.h>
#include <stdio.h>

/* Optional debugging settings, specified at runtime */
extern bool DEBUG;       /* Set inside of enumy.c */
extern bool DEBUG_EXTRA; /* Set inside of enumy.c */

/* This function will only be executed if the runtime argument */
/* -d 1 or -d 2 is passed */
#define DEBUG_PRINT(fmt, ...)                             \
    do                                                    \
    {                                                     \
        if (DEBUG)                                        \
            fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                    __LINE__, __func__, __VA_ARGS__);     \
    } while (0)

/* This function will only be executed if the runtime argument */
/* -d 2 is passed */
#define DEBUG_PRINT_EXTRA(fmt, ...)                                     \
    do                                                                  \
    {                                                                   \
        if (DEBUG_EXTRA)                                                \
            fprintf(stderr, "debug extra-> %s:%d:%s(): " fmt, __FILE__, \
                    __LINE__, __func__, __VA_ARGS__);                   \
    } while (0)
