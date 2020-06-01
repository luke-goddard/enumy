/*
    This files job is to kick of all the scans currently there are two types 
    of scans FILE scans and SYSTEM scans. The first will scan a file and the 
    second scans do not require a file for example open ports etc. 
*/

#include "results.h"
#include "main.h"
#include "file_system.h"
#include "vector.h"
#include "thpool.h"
#include "debug.h"
#include "scan.h"
#include "reporter.h"
#include "error_logger.h"

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <thpool.h>
#include <string.h>
#include <stdbool.h>

/* ============================ STRUCTS ============================== */

typedef struct Walk_Args
{
    char *walk_path;          /* Root location to walk the file system */
    All_Results *all_results; /* This is a struct to hold the results  */
    Args *cmdline;            /* This is the command line arguments    */
    vec_void_t *users;        /* Parsed /etc/passwd file */
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
    // vec_void_t *users = thread_pool_args->users;

    /* Failed to allocate memory */
    if (stat_buf == NULL)
    {
        if (new_file != NULL)
            free(new_file);

        free(thread_pool_args);
        log_fatal_errno("Failed to allocate memory for the stat buf", errno);
        exit(EXIT_FAILURE);
    }
    if (new_file == NULL)
    {
        if (stat_buf != NULL)
            free(stat_buf);

        free(thread_pool_args);
        log_fatal_errno("Failed to allocate memory for the new_file struct", errno);
        exit(EXIT_FAILURE);
    }

    /* Populate the new file structure */
    strncpy(new_file->location, thread_pool_args->file_location, sizeof(new_file->location) - 1);
    strncpy(new_file->name, thread_pool_args->file_name, sizeof(new_file->location) - 1);
    get_file_extension(new_file->extension, thread_pool_args->file_location);

    if (lstat(thread_pool_args->file_location, stat_buf) == 0)
        new_file->stat = stat_buf;
    else
    {
        log_error_errno_loc(thread_pool_args->all_results, "Failed to run lstat on file", thread_pool_args->file_location, errno);
        goto END;
    }

    /* Ignore symlinks as following them to special files will break scans */
    if (S_ISLNK(stat_buf->st_mode))
        goto END;

    /* ============================ KICK OFF FILE SCANS ============================== */

    suid_bit_scan(new_file, thread_pool_args->all_results);
    guid_bit_scan(new_file, thread_pool_args->all_results);
    capabilities_scan(new_file, thread_pool_args->all_results, thread_pool_args->cmdline);
    intresting_files_scan(new_file, thread_pool_args->all_results);
    core_dump_scan(new_file, thread_pool_args->all_results);
    rpath_scan(new_file, thread_pool_args->all_results, thread_pool_args->cmdline);
    lotl_scan(new_file, thread_pool_args->all_results);

    /* ============================ FINISH FILE SCANS ============================== */

    pthread_mutex_lock(&FilesScannedMutex);
    FilesScanned++;
    pthread_mutex_unlock(&FilesScannedMutex);

END:
    free(stat_buf);
    free(new_file);
    free(thread_pool_args);
}

/**
 * This is the main entry point to kick off all of the scans. This function will create a 
 * thread for the file scans and then run the system scans in the current thread 
 * @param results this is a structure containing linked lists for the results to be stored 
 * @param args This is the run time arguments specified by the user 
 */
void start_scan(All_Results *all_results, Args *args)
{
    vec_str_t valid_shared_libs;
    pthread_t walk_thread;
    char *retval;

    /* Populate the standard shared libaries locations */
    args->valid_shared_libs = &valid_shared_libs;
    find_shared_libs(args->valid_shared_libs);

    /* ============================ KICK OFF SYSTEM SCANS ============================== */

    current_user_scan();
    sys_scan(all_results);
    sshd_conf_scan(all_results);
    vec_void_t *users = passwd_scan(all_results);

    struct Walk_Args walk_args = {
        .walk_path = args->walk_dir,
        .all_results = all_results,
        .cmdline = args,
        .users = passwd_scan(all_results)};

    /* Walk the file system in the background while we perform other scans */
    pthread_create(&walk_thread, NULL, create_walk_thread, &walk_args);
    pthread_join(walk_thread, (void **)&retval);

    /* ============================ FINISH SYSTEM SCANS ============================== */

    /* Save results as a JSON file */
    save_as_json(all_results, args);
    printf("Total files scanned -> %i\n", FilesScanned);

    /* Cleanup */
    free_shared_libs(args->valid_shared_libs);
    free_users(users);
}

/* ============================ STATIC FUNCTIONS ============================== */

/**
 * This is the entry point for the file_system scans. This thread
 * will walk the entire file system and then test each file against tests.
 * @param args This is a pointer the Walk_Args struct
 */
static void *create_walk_thread(void *args)
{
    Walk_Args *arguments = (Walk_Args *)args;
    All_Results *all_results = arguments->all_results;
    char *walk_path = arguments->walk_path;
    Args *cmdline = arguments->cmdline;
    vec_void_t *users = arguments->users;

    /* Create the threadpool */
    cmdline->fs_threadpool = thpool_init(cmdline->fs_threads);

    /* Walk the file system adding each file to the thread pool */
    walk_file_system(walk_path, all_results, cmdline, users);

    /* Cleanup */
    thpool_destroy(cmdline->fs_threadpool);
    return NULL;
}
