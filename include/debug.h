#pragma once

#include <stdbool.h>

extern bool DEBUG;
extern bool DEBUG_EXTRA;

#define DEBUG_PRINT(fmt, ...)                             \
    do                                                    \
    {                                                     \
        if (DEBUG)                                        \
            fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                    __LINE__, __func__, __VA_ARGS__);     \
    } while (0)

#define DEBUG_PRINT_EXTRA(fmt, ...)                                     \
    do                                                                  \
    {                                                                   \
        if (DEBUG_EXTRA)                                                \
            fprintf(stderr, "debug extra-> %s:%d:%s(): " fmt, __FILE__, \
                    __LINE__, __func__, __VA_ARGS__);                   \
    } while (0)
