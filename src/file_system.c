/* 
    This file is used to populate an array of files in the system 
    each file stored in the array will have permissions etc. We can
    use this to find SUID binaries and writeable config files etc
*/

#include "file_system.h"
#include "results.h"
#include "scan.h"
#include "thpool.h"
#include "debug.h"

#include <stdlib.h>
#include <libgen.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <ctype.h>

/* ============================ PROTOTYPES ============================== */

void walk_file_system(char *entry_location, All_Results *all_results, Args *cmdline);

bool has_extension(File_Info *f, char *extension);
bool has_global_write(File_Info *f);
bool has_global_read(File_Info *f);
bool has_global_execute(File_Info *f);
bool has_group_write(File_Info *f);
bool has_group_execute(File_Info *f);
bool has_executable(File_Info *f);
bool has_suid(File_Info *fi);
bool has_guid(File_Info *fi);
bool can_read(File_Info *fi);

char *get_file_name(char *full_path);
char *get_dir_name(char *full_path);
void get_file_extension(char *buf, char *f_name);
bool is_folder_writable(char *path);

static void add_file_to_thread_pool(char *file_location, char *file_name, All_Results *all_results, Args *cmdline);

/* ============================ FUNCTIONS ============================== */

/**
 * Walks the file system, will skip files in ignore directory (cmdline arguments)
 * For each path encountered it will pass the file to a thread pool 
 * The thread pool will perform scans on the file 
 * Note this scan will not walk the proc file system 
 * @param entry_location the root location to walk 
 * @param all_results a pointer to structure containinng all the future enumy findings 
 * @param cmdline a pointer to the run time arguments 
 */
void walk_file_system(char *entry_location, All_Results *all_results, Args *cmdline)
{
    DIR *dir;
    struct dirent *entry;
    char file_location[MAXSIZE - 1] = {0};

    dir = opendir(entry_location);

    if (dir == NULL)
    {
        DEBUG_PRINT("Failed to open directory at location %s\n", entry_location);
        DEBUG_PRINT("Error -> %s\n", strerror(errno));
        return;
    }

    DEBUG_PRINT_EXTRA("Walking dir at location -> %s\n", entry_location);

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
        {
            if (entry->d_type & DT_REG)
            {
                DEBUG_PRINT_EXTRA("Found file %s\n", entry->d_name);
                strncpy(file_location, entry_location, sizeof(file_location) - 1);
                strncat(file_location, entry->d_name, sizeof(file_location) - 1 - strlen(file_location));
                add_file_to_thread_pool(file_location, entry->d_name, all_results, cmdline);
            }
            else if (entry->d_type & DT_DIR)
            {
                DEBUG_PRINT_EXTRA("Found folder %s\n", entry->d_name);
                strncpy(file_location, entry_location, sizeof(file_location) - 1);
                strncat(file_location, entry->d_name, sizeof(file_location) - 1 - strlen(file_location));
                if (
                    strcmp(cmdline->ignore_scan_dir, file_location) == 0 ||
                    strcmp("/proc", file_location) == 0 ||
                    strcmp("/sys", file_location) == 0)
                    continue;

                strncat(file_location, "/", sizeof(file_location) - 1 - strlen(file_location));
                if (strcmp(cmdline->ignore_scan_dir, file_location) == 0)
                    continue;

                walk_file_system(file_location, all_results, cmdline);
            }
            else
                DEBUG_PRINT_EXTRA("Found unknown file type -> %s, %i\n", entry->d_name, entry->d_type);
        }
    }
    closedir(dir);
}

/* ============================ has_* FUNCTIONS ============================== */

/**
 * Tests to see if other read is enabled 
 * @param fi this is the current file that's being scanned 
 */
bool has_global_read(File_Info *f)
{
    return f->stat->st_mode & S_IROTH;
}

/**
 * Tests to see if other write is enabled 
 * @param fi this is the current file that's being scanned 
 */
bool has_global_write(File_Info *f)
{
    return f->stat->st_mode & S_IWOTH;
}

/**
 * Tests to see if other execute is enabled 
 * @param fi this is the current file that's being scanned 
 */
bool has_global_execute(File_Info *f)
{
    return f->stat->st_mode & S_IXOTH;
}

/**
 * Tests to see if group execute is enabled 
 * @param fi this is the current file that's being scanned 
 */
bool has_group_execute(File_Info *f)
{
    return f->stat->st_mode & S_IXGRP;
}

/**
 * Tests to see if group write is enabled 
 * @param fi this is the current file that's being scanned 
 */
bool has_group_write(File_Info *f)
{
    return f->stat->st_mode & S_IWGRP;
}

/**
 * Tests to see if the current file has SUID bit enabled 
 * @param fi this is the current file that's being scanned 
 */
bool has_suid(File_Info *f)
{
    return f->stat->st_mode & S_ISUID;
}

/**
 * Tests to see if the current file has GUID bit enabled
 * @param fi this is the current file that's being scanned 
 */
bool has_guid(File_Info *f)
{
    return f->stat->st_mode & S_ISGID;
}

/**
 * Tests to see if the current file has a matching extension
 * @param fi this is the current file that's being scanned 
 * @param extension this is the extension to check against
 */
bool has_extension(File_Info *f, char *extension)
{
    return strcmp(f->extension, extension);
}

/**
 * Tests to see if the group or other can execute the file 
 * @param fi this is the current file that's being scanned 
 */
bool has_executable(File_Info *f)
{
    return (has_group_execute(f) || has_global_execute(f));
}

/**
 * Tests to see if the file is readable by the current process 
 * @param fi this is the current file that's being scanned 
 */
bool can_read(File_Info *fi)
{
    return access(fi->location, R_OK) == 0;
}

/* ============================ get_* FUNCTIONS ============================== */

/**
* Get the file extension the "." is not saved and an extension
* abc.tar.gz would return .gz not .tar.gz
* The extensions is saved in lowercase
* @param buffer location to save the file extension
* @param f_name the files name 
*/
void get_file_extension(char *buf, char *f_name)
{
    int size = strlen(f_name) - 1;
    int i = 0;
    buf[0] = '\0';

    if (size > MAX_FILE_SIZE - 1)
    {
        DEBUG_PRINT("Found a file with an extension bigger than buffer size -> %s\n", f_name);
        return;
    }

    for (int x = size; x >= 0; x--)
    {
        if (f_name[x] == '.' && x != 0 && size - x < MAX_EXTENSION_SIZE)
        {
            for (int y = x + 1; y <= size; y++)
            {
                buf[i] = (char)tolower(f_name[y]);
                i++;
            }
            buf[i] = '\0';
            return;
        }
    }
    buf[0] = '\0';
}

/**
 * Given a full path this function returns the file path 
 * @param full_path the files full path
 * @return a heap pointer containing the file's name
 */
char *get_file_name(char *full_path)
{
    char *loc = strrchr(full_path, '/');

    if (loc == NULL)
    {
        return NULL;
    }

    if (strlen(loc + 1) != 0)
    {
        return loc + 1;
    }
    return NULL;
}

/**
 * Given a full path this function will return all the files parent directorys 
 * DONT forget to free the returned pointer 
 * @param full_path the files full path 
 * @return a heap pointer containing the files's directory name 
 */
char *get_dir_name(char *full_path)
{
    return dirname((char *)strdup(full_path));
}

/* ============================ is_* FUNCTIONS ============================== */

/**
 * Given a directory returns true if the current process 
 * can write to that directory 
 * @param path location to test if writable
 */
bool is_folder_writable(char *path)
{
    return access(path, W_OK) == 0;
}

/* ============================ STATIC FUNCTIONS ============================== */

/**
 * Adds the file at to the thread pool of scans to perform
 * This function blocks if the thread pool is at maxiumum capacity 
 * @param file_location the file to be scaned 
 * @param file_name the name of the file that is going to be ccaned 
 */
static void add_file_to_thread_pool(char *file_location, char *file_name, All_Results *all_results, Args *cmdline)
{
    Thread_Pool_Args *args = malloc(sizeof(Thread_Pool_Args));

    if (args == NULL)
    {
        printf("Failed to allocate memort when adding file to the thread pool");
        exit(EXIT_FAILURE);
    }

    DEBUG_PRINT_EXTRA("Scanning file -> %s\n", file_location);

    memset(args->file_location, '\0', sizeof args->file_location);
    strncpy(args->file_location, file_location, sizeof(args->file_location));
    strncpy(args->file_name, file_name, sizeof(args->file_name));

    args->all_results = all_results;
    args->cmdline = cmdline;

    while (thpool_jobqueue_length(cmdline->fs_threadpool) > cmdline->fs_threads * 2)
        usleep(200);

    thpool_add_work(cmdline->fs_threadpool, (void *)scan_file_for_issues, (void *)args);
}