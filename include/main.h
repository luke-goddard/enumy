/*
    Commonly used structs and defines that don't really relate to any part of code 
    in particular 
*/

#pragma once

#include <stdbool.h>
#include <thpool.h>
#include <vector.h>

/* ============================ DEFINES ============================== */

#define VERSION "v1.05" /* Enumy's version */
#define MAXSIZE 2049    /* Arbitrary maximum size for some buffers */

/* ============================ STRUCTS ============================== */

typedef struct Args
{
    char save_location[MAXSIZE + 1];   /* Location to save the enumy results   */
    char ignore_scan_dir[MAXSIZE + 1]; /* Don't walk files in this location    */
    char walk_dir[MAXSIZE + 1];        /* Root location to walk, normally "/"  */

    bool enabled_full_scans; /* Runs more computationally expensive scans */
    bool enabled_ncurses;    /* Enables the ncurse interface */
    bool enabled_missing_so; /* Enables scanning for missing shared objects */

    int fs_threads;           /* Number of threads avaliable for the thread pool */
    threadpool fs_threadpool; /* Thread pool used for file system scans */

    vec_str_t *valid_shared_libs; /* Vector that holds standard shared object files */
} Args;