/* 
    This file is used to populate an array of files in the system 
    each file stored in the array will have permissions etc. We can
    use this to find SUID binaries and writeable config files etc
*/

#include "file_system.h"
#include "utils.h"
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

static void add_file_to_thread_pool(char *file_location, char *file_name, All_Results *all_results, Args *cmdline);

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
    char file_location[MAXSIZE];

    file_location[0] = '\0';

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
                strncpy(file_location, entry_location, MAXSIZE - 1);
                strcat(file_location, entry->d_name);
                add_file_to_thread_pool(file_location, entry->d_name, all_results, cmdline);
            }
            else if (entry->d_type & DT_DIR)
            {
                DEBUG_PRINT_EXTRA("Found folder %s\n", entry->d_name);
                strncpy(file_location, entry_location, MAXSIZE - 1);
                strcat(file_location, entry->d_name);
                if (strcmp(cmdline->ignore_scan_dir, file_location) == 0)
                {
                    continue;
                }
                if (strcmp("/proc", file_location) == 0)
                {
                    continue;
                }
                if (strcmp("/sys", file_location) == 0)
                {
                    continue;
                }
                strcat(file_location, "/");
                if (strcmp(cmdline->ignore_scan_dir, file_location) == 0)
                {
                    continue;
                }
                walk_file_system(file_location, all_results, cmdline);
            }
            else
            {
                DEBUG_PRINT_EXTRA("Found unknown file type -> %s, %i\n", entry->d_name, entry->d_type);
            }
        }
    }
    closedir(dir);
}

/**
 * Adds the file at to the thread pool of scans to perform
 * This function blocks if the thread pool is at maxiumum capacity 
 * @param file_location the file to be scaned 
 * @param file_name the name of the file that is going to be ccaned 
 */
static void add_file_to_thread_pool(char *file_location, char *file_name, All_Results *all_results, Args *cmdline)
{
    int loops = 0;
    Thread_Pool_Args *args = malloc(sizeof(Thread_Pool_Args));

    if (args == NULL)
    {
        out_of_memory_err();
    }

    DEBUG_PRINT_EXTRA("Scanning file -> %s\n", file_location);

    strncpy(args->file_location, file_location, MAXSIZE - 1);
    strncpy(args->file_name, file_name, MAXSIZE - 1);
    args->all_results = all_results;
    args->cmdline = cmdline;

    while (thpool_jobqueue_length(cmdline->fs_threadpool) > cmdline->fs_threads * 2)
    {
        usleep(200);
        loops++;
        if (loops > 1000)
        {
            DEBUG_PRINT("Potential DEADLOCK found when walking at location -> %s\n", file_location);
        }
    }

    thpool_add_work(cmdline->fs_threadpool, (void *)scan_file_for_issues, (void *)args);
}

/**
* Get the file extension the "." is not saved and an extension
* abc.tar.gz would return .gz not .tar.gz
* The extensions is saved in lowercase
* @param buffer location to save the file extension
* @param f_name the files name 
*/
void get_file_extension(char *buf, char *f_name)
{
    int size = strlen(f_name);
    int i = 0;
    char current;

    if (size > MAX_FILE_SIZE - 1)
    {
        DEBUG_PRINT("Found a file with an extension bigger than buffer size -> %s\n", f_name);
        return;
    }

    for (int x = size; x >= 0; x--)
    {
        current = f_name[x];
        if (current == '.' && x != 0 && size - x < MAX_EXTENSION_SIZE)
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

bool has_global_read(File_Info *f)
{
    return f->stat->st_mode & S_IROTH;
}

bool has_global_write(File_Info *f)
{
    return f->stat->st_mode & S_IWOTH;
}

bool has_global_execute(File_Info *f)
{
    return f->stat->st_mode & S_IXOTH;
}

bool has_group_execute(File_Info *f)
{
    return f->stat->st_mode & S_IXGRP;
}

bool has_group_write(File_Info *f)
{
    return f->stat->st_mode & S_IWGRP;
}

bool has_suid(File_Info *f)
{
    return f->stat->st_mode & S_ISUID;
}

bool has_guid(File_Info *f)
{
    return f->stat->st_mode & S_ISGID;
}

bool has_extension(File_Info *f, char *extension)
{
    return strcmp(f->extension, extension);
}

bool has_executable(File_Info *f)
{
    return (has_group_execute(f) || has_global_execute(f));
}

bool can_read(File_Info *fi)
{
    return access(fi->location, R_OK) == 0;
}

/**
 * Given a full path this function returns the file path 
 * DONT forget to free the returned pointer
 * @param full_path the files full path
 * @return a heap pointer containing the file's name
 */
char *get_file_name(char *full_path)
{
    char *s = strrchr(full_path, '/');
    if (!s)
        return strdup(full_path);
    else
        return strdup(s + 1);
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

/**
 * Given a directory returns true if the current process 
 * can write to that directory 
 * @param path location to test if writable
 */
bool is_folder_writable(char *path)
{
    if (access(path, W_OK) == 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}