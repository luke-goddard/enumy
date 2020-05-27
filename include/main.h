/*
    CHANGE ME 
*/

#pragma once

#include <stdbool.h>
#include <thpool.h>
#include <vector.h>

/* ============================ DEFINES ============================== */

#define MAXSIZE 2048
#define VERSION "v1.05"

/* ============================ STRUCTS ============================== */

typedef struct Args
{
    char save_location[MAXSIZE + 1];
    char ignore_scan_dir[MAXSIZE + 1];
    char walk_dir[MAXSIZE + 1];

    bool enabled_full_scans;
    bool enabled_ncurses;
    bool enabled_missing_so;

    int fs_threads;

    threadpool fs_threadpool;

    Vector *valid_shared_libs;
} Args;