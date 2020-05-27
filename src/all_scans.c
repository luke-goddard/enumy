/*
    This files job is to kick of all the scans
*/

#include "results.h"
#include "main.h"
#include "file_system.h"
#include "utils.h"
#include "vector.h"
#include "thpool.h"
#include "debug.h"
#include "scan.h"
#include "reporter.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <thpool.h>
#include <string.h>
#include <stdbool.h>

/* ============================ STRUCTS ============================== */

typedef struct Walk_Args
{
    char *walk_path;
    All_Results *all_results;
    Args *cmdline;
} Walk_Args;

/* ============================ GLOBAL VARS ============================== */

pthread_mutex_t FilesScannedMutex;
int FilesScanned = 0;

/* ============================ PROTOTYPES ============================== */

void start_scan(All_Results *all_results, Args *args);
void scan_file_for_issues(Thread_Pool_Args *thread_pool_args);

static void *create_walk_thread(void *args);

/* ============================ FUNCTIONS ============================== */

/** 
 * This kicks of all the scans for the current file found by walking the file system in a seperate thread 
 * @param thread_pool_args this is structure containing all the information needed to kick off the scan
 */
void scan_file_for_issues(Thread_Pool_Args *thread_pool_args)
{
    struct File_Info *new_file = (File_Info *)malloc(sizeof(File_Info));
    struct stat *stat_buf = malloc(sizeof(struct stat));
    int findings = 0;

    if (stat_buf == NULL)
    {
        if (new_file != NULL)
            free(new_file);

        free(thread_pool_args);
        out_of_memory_err();
    }
    if (new_file == NULL)
    {
        if (stat_buf != NULL)
            free(stat_buf);

        free(thread_pool_args);
        out_of_memory_err();
    }

    strncpy(new_file->location, thread_pool_args->file_location, sizeof(new_file->location) - 1);
    strncpy(new_file->name, thread_pool_args->file_name, sizeof(new_file->location) - 1);
    get_file_extension(new_file->extension, thread_pool_args->file_location);

    if (lstat(thread_pool_args->file_location, stat_buf) == 0)
    {
        new_file->stat = stat_buf;
    }
    else
    {
        DEBUG_PRINT("lstat failed to get information for -> %s\n", new_file->location);
        goto end;
    }

    // Ignore symlinks as following them to special files will break scans
    if (S_ISLNK(stat_buf->st_mode))
        goto end;

    findings += suid_bit_scan(new_file, thread_pool_args->all_results, thread_pool_args->cmdline);
    findings += guid_bit_scan(new_file, thread_pool_args->all_results, thread_pool_args->cmdline);
    findings += capabilities_scan(new_file, thread_pool_args->all_results, thread_pool_args->cmdline);
    findings += intresting_files_scan(new_file, thread_pool_args->all_results, thread_pool_args->cmdline);
    findings += core_dump_scan(new_file, thread_pool_args->all_results, thread_pool_args->cmdline);
    findings += rpath_scan(new_file, thread_pool_args->all_results, thread_pool_args->cmdline);

    lotl_scan(new_file, thread_pool_args->all_results, thread_pool_args->cmdline);

    pthread_mutex_lock(&FilesScannedMutex);
    FilesScanned++;
    pthread_mutex_unlock(&FilesScannedMutex);

end:
    free(stat_buf);
    free(new_file);
    free(thread_pool_args);
}

/**
 * This kicks of all of the scans for enumy 
 * @param layout a pointer to the ncurses layout
 * @param all_results a structure containing all of the results that enumy finds
 * @param args a structure containing all of the commandline arguments
 */
void start_scan(All_Results *all_results, Args *args)
{
    pthread_t walk_thread;
    char *retval;

    struct Walk_Args walk_args = {
        .walk_path = args->walk_dir,
        .all_results = all_results,
        .cmdline = args};

    args->valid_shared_libs = find_shared_libs();

    current_user_scan();

    if (!args->enabled_ncurses)
    {
        printf("Walking file system at location -> %s\n", args->walk_dir);
    }

    // Walk the file system in the background while we perform other scans
    pthread_create(&walk_thread, NULL, create_walk_thread, &walk_args);

    sys_scan(all_results, args);
    sshd_conf_scan(all_results, args);

    pthread_join(walk_thread, (void **)&retval);

    save_as_json(all_results, args);

    printf("Total files scanned -> %i\n", FilesScanned);
    free_total_results(all_results);
    free_shared_libs(args->valid_shared_libs);
}

/* ============================ STATIC FUNCTIONS ============================== */

/**
 * This is the entry point for the file_system scans. This thread
 * will walk the entire file system and then test each file against
 * tests.
 * @param args This is a pointer the Walk_Args struct
 */
static void *create_walk_thread(void *args)
{
    Walk_Args *arguments = (Walk_Args *)args;
    All_Results *all_results = arguments->all_results;
    char *walk_path = arguments->walk_path;
    Args *cmdline = arguments->cmdline;

    cmdline->fs_threadpool = thpool_init(cmdline->fs_threads);

    walk_file_system(walk_path, all_results, cmdline);
    thpool_destroy(cmdline->fs_threadpool);
    return NULL;
}