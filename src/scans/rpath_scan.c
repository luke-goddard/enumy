/*
    This scan will parse elf file and then look in the .dynamic section of the binary 
    for the following tags.

    DT_RPATH    String table offset to library search path (deprecated)
    DT_RUNPATH  String table offset to library search path
    DT_NEEDED   String table offset to name of a needed library

    the run paths (DT_RPATH and DT_RUNPATH) are used to find libaries needed similar to 
    the $PATH variable for finding executables. The precedence is the following: 

    1. DT_RPATH
    2. LD_LIBRARY_PATH
    3. DT_RUNPATH 

    If the file is determined to be an elf file we first find out what shared libaries 
    are required by itterating through the .dynamic section looking for the DT_NEEDED 
    tag. This points to the names of the shared libaries required to execute. Next we
    search for the shared libary if we find it's missing or a search location with higher
    precedence is does not contain the shared libary and this location is writable then
    we will report this as an issue. 

    This scan is slow because we have to parse millions of files so it's only enabled in 
    the full scan option

    Note DT_RPATH and DT_RUNPATH can be tokenized with semicolons e.g
    DT_RUNPATH:-> $ORIGIN/../../lib

    The $ORIGIN value means replace with the binaries current directory 

    for testing I used the level 15 binary from the nebular CTF. 
*/

#define _GNU_SOURCE

#include "file_system.h"
#include "main.h"
#include "results.h"
#include "scan.h"
#include "elf_parsing.h"
#include "debug.h"
#include "utils.h"
#include "vector.h"

#include <stdio.h>
#include <err.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MISSING false
#define INJECT true

typedef struct Lib_Info
{
    Tag_Array *dt_needed;  // All the shared libaries files names
    Tag_Array *dt_rpath;   // High precedence
    Tag_Array *dt_runpath; // Low precedence
} Lib_Info;

int rpath_scan(File_Info *fi, All_Results *ar, Args *cmdline);
static int test_missing_shared_libaries(Lib_Info *lib_info, File_Info *fi, All_Results *ar, Args *cmdline);
static Lib_Info *get_lib_info(Elf_File *elf);
static void free_lib_info(Lib_Info *lib_info);
static bool search_shared_lib_in_dir(char *lib_name, char *location);
static bool search_for_injectable(char *search_for, Tag_Array *tag, char *origin, File_Info *fi, All_Results *all_results, Args *cmdline);
static bool search_dyn_path_for_missing(char *search_for, Tag_Array *tag, char *origin);
static bool search_dyn_path(char *search_for, Tag_Array *tag, char *origin, bool mode, File_Info *fi, All_Results *ar, Args *cmdline);

/**
 * Given a file this function will determine if the file is an elf
 * if the file is an elf and can be parsed then we try and find the shared
 * objects dependendcies. We pass these dependenceies to other scans
 * @param fi The current files information 
 * @param ar The struct containing all of enumy's findings 
 * @param cmdline The struct containing runtime arguments 
 */
int rpath_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;

    if (cmdline->enabled_full_scans != true)
    {
        return findings;
    }

    int arch = has_elf_magic_bytes(fi);
    if (
        (arch == 0) ||
        (arch == 1 && sizeof(char *) != 4) ||
        (arch == 2 && sizeof(char *) != 8))
    {
        return findings;
    }

    Elf_File *elf = parse_elf(fi);
    if (elf == NULL)
    {
        DEBUG_PRINT("Failed to parse elf at location -> %s\n", fi->location);
        return findings;
    }

    elf_parse_dynamic_sections(elf);

    Lib_Info *lib_info = get_lib_info(elf);

    findings += test_missing_shared_libaries(lib_info, fi, ar, cmdline);

    close_elf(elf, fi);
    free_lib_info(lib_info);

    return findings;
}

/**
 * Takes an Elf_File and then searches the dynamic section for 3 tags, DT_NEEDED
 * DT_RPATH and DT_RUNPATH. Creates a struct containing the results
 * @param elf pointer to an Elf_File that has allready been parsed
 * @return a pointer to results
 */
static Lib_Info *get_lib_info(Elf_File *elf)
{
    Lib_Info *lib_info = malloc(sizeof(Lib_Info));

    if (lib_info == NULL)
    {
        out_of_memory_err();
    }

    lib_info->dt_needed = search_dynamic_for_value(elf, DT_NEEDED);
    lib_info->dt_rpath = search_dynamic_for_value(elf, DT_RPATH);
    lib_info->dt_runpath = search_dynamic_for_value(elf, DT_RUNPATH);

    return lib_info;
}

static void free_lib_info(Lib_Info *lib_info)
{
    free(lib_info);
}

/**
 * Itterates through the required shared objects for an ELF File then tries to find them on the system. 
 * First the RPATH is searchedd
 * Second the standard files inside /usr/lib etc are searched 
 * Third the RUNPATH is searched 
 * @param lib_info struct containg vectors containing all of the shared object information parsed from .dynamic 
 * @param fi struct containing the elf files information
 * @param ar Linked list containg all issues found on the system
 * @param cmdline struct containing runtime arguments 
 * @return retuns the number of missing shared objects for the given elf file 
 */
static int test_missing_shared_libaries(Lib_Info *lib_info, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;
    char *origin;

    if (lib_info->dt_needed == NULL)
    {
        // Does not need any shared libs
        return findings;
    }

    origin = get_dir_name(fi->location);

    if (origin == NULL)
    {
        DEBUG_PRINT("Failed to get $ORIGIN for path %s\n", fi->location);
        return findings;
    }

    strcat(origin, "/");

    for (int i = 0; i < lib_info->dt_needed[0].size; i++)
    {
        if (strcasestr(lib_info->dt_needed[i].tag_value, ".so") == NULL)
        {
            DEBUG_PRINT("Probably failed to parse DT_NEEDED at location %s with value -> '%s'\n", fi->location, lib_info->dt_needed[i].tag_value);
            continue;
        }

        // check rpath
        if (search_dyn_path_for_missing(lib_info->dt_needed[i].tag_value, lib_info->dt_rpath, origin))
        {
            // printf("Found dt-needed in one of the dt_rpaths %s\n", fi->location);
            continue;
        }

        // It's not in rpath, do we have control to anwhere in rpath?
        if (search_for_injectable(lib_info->dt_needed[i].tag_value, lib_info->dt_rpath, origin, fi, ar, cmdline))
        {
            break;
        }

        // exit(EXIT_SUCCESS);

        // Check normal shared objects in /usr/lib etc
        if (test_if_standard_shared_object(cmdline->valid_shared_libs, lib_info->dt_needed[i].tag_value))
        {
            // printf("Found the shared libary in the standard location %s\n", fi->location);
            continue;
        }

        // check run_path
        if (search_dyn_path_for_missing(lib_info->dt_needed[i].tag_value, lib_info->dt_runpath, origin))
        {
            // printf("Found the shared object in dt_runpath%s\n", fi->location);
            continue;
        }
        // It's not in rpath, do we have control to anwhere in rpath?
        if (search_for_injectable(lib_info->dt_needed[i].tag_value, lib_info->dt_runpath, origin, fi, ar, cmdline))
        {
            break;
        }

        // This shared object is missing
        if (cmdline->enabled_missing_so)
        {
            int id = 234;
            char name[MAXSIZE + 100];
            Result *new_result = create_new_issue();
            snprintf(name, MAXSIZE, "Missing shared libary %s", lib_info->dt_needed[i].tag_value);
            set_id_and_desc(id, new_result);
            set_issue_location(fi->location, new_result);
            set_issue_name(name, new_result);
            add_new_result_info(new_result, ar, cmdline);
        }
    }

    free(origin);
    return findings;
}

/**
 * Itterates through the tag array trying to find the missing/unfound 
 * shared libary 
 * @param search_for the shared object required by the executable
 * @param Tag_Array the parsed data from .dym section of the binary
 * @param origin what $ORIGIN will me replaced with (see man elf rpath)
 * @return true if shared object has been found
 */
static bool search_dyn_path_for_missing(char *search_for, Tag_Array *tag, char *origin)
{
    return search_dyn_path(search_for, tag, origin, MISSING, NULL, NULL, NULL);
}

/**
 * Only call if search_dyn_path_for_missing returned false. This means 
 * that the file shared objects could be injectable we just need to find 
 * a place where we can inject them. 
 * If found then issue will be added to the issue list 
 * @param search_for the shared object required by the executable
 * @param Tag_Array the parsed data from .dym section of the binary
 * @param origin what $ORIGIN will me replaced with (see man elf rpath)
 * @param fi struct containing the elf files information
 * @param ar Linked list containg all issues found on the system
 * @param cmdline struct containing runtime arguments 
 * @return true if an injectable location has been found
 */
static bool search_for_injectable(char *search_for, Tag_Array *tag, char *origin, File_Info *fi, All_Results *all_results, Args *cmdline)
{
    return search_dyn_path(search_for, tag, origin, INJECT, fi, all_results, cmdline);
}

/**
 * You should search_dyn_path_for_missing or search_for_injectable, not this 
 * function directly 
 * 
 * Itterates through the RPATH or RUNPATH tag array, searching for the value
 * will replace $ORIGIN with the full path to the base name of the executable
 * The tag array can contain multiple tag_values
 * Tag values can contain multiple paths tokenized with a colon
 * Example tag value "$ORIGIN:/tmp"
 * @param search_for the shared object required by the executable
 * @param Tag_Array the parsed data from .dym section of the binary
 * @param origin what $ORIGIN will me replaced with (see man elf rpath)
 * @param mode true to search for shared objects and false to search for injectable paths
 * @param ar Linked list containg all issues found on the system (Can be null if mode == MISSING)
 * @param cmdline struct containing runtime arguments (Can be null if mode == MISSING)
 * @return true if shared object has been found
 */
static bool search_dyn_path(char *search_for, Tag_Array *tag, char *origin, bool mode,
                            File_Info *fi, All_Results *ar, Args *cmdline)
{
    char search_location[MAXSIZE];
    char *current_rpath;
    char current_character;
    int buf_copy_loc;
    int tag_size;

    if (tag == NULL)
    {
        return false;
    }

    // Itterate through each path tag found in binary
    for (int i = 0; i < tag[0].size; i++)
    {
        current_rpath = tag[i].tag_value;
        buf_copy_loc = 0;

        tag_size = (int)strlen(current_rpath);
        // Itterate through each character in a tag (tokenized with ":")
        for (int y = 0; y < tag_size; y++)
        {
            current_character = current_rpath[y];
            if (current_character == ':')
            {
                search_location[buf_copy_loc] = '\0';
                buf_copy_loc = 0;

                if (strcmp("$ORIGIN", search_location) == 0)
                {
                    if (fi != NULL && has_suid(fi))
                    {
                        int id = 236;
                        Result *new_result = create_new_issue();
                        char *name = "SUID binary with $ORIGIN";
                        set_id_and_desc(id, new_result);
                        set_other_info(search_for, new_result);
                        set_issue_location(fi->location, new_result);
                        set_issue_name(name, new_result);
                        add_new_result_high(new_result, ar, cmdline);
                        return true;
                    }
                    if (mode == MISSING && search_shared_lib_in_dir(search_for, origin))
                    {
                        return true;
                    }
                    if (fi != NULL && mode == INJECT && is_folder_writable(search_location))
                    {
                        int id = 235;
                        char name[MAXSIZE + 100];
                        Result *new_result = create_new_issue();
                        snprintf(name, MAXSIZE + 100, "Shared obj injection at -> %s", search_location);
                        set_id_and_desc(id, new_result);
                        set_other_info(search_for, new_result);
                        set_issue_location(fi->location, new_result);
                        set_issue_name(name, new_result);
                        add_new_result_high(new_result, ar, cmdline);
                        return true;
                    }
                }
                else
                {
                    if (mode == MISSING && search_shared_lib_in_dir(search_for, search_location))
                    {
                        return true;
                    }
                    if (mode == INJECT && is_folder_writable(search_location))
                    {
                        int id = 235;
                        char name[MAXSIZE + 100];
                        Result *new_result = create_new_issue();
                        snprintf(name, MAXSIZE + 100, "Shared obj injection at -> %s", search_location);
                        set_id_and_desc(id, new_result);
                        set_other_info(search_for, new_result);
                        set_issue_location(fi->location, new_result);
                        set_issue_name(name, new_result);
                        add_new_result_high(new_result, ar, cmdline);
                        return true;
                    }
                }
                search_location[buf_copy_loc] = '\0';
            }
            else
            {
                search_location[buf_copy_loc] = current_character;
                buf_copy_loc++;
            }
        }

        search_location[buf_copy_loc + 1] = '\0';
        // printf("RPath -> %s\n", search_location);
        if (strcmp("$ORIGIN", search_location) == 0)
        {
            if (mode == MISSING && search_shared_lib_in_dir(search_for, origin))
            {
                return true;
            }
            if (mode == INJECT && is_folder_writable(search_location))
            {
                int id = 235;
                char name[MAXSIZE + 100];
                Result *new_result = create_new_issue();
                snprintf(name, MAXSIZE + 100, "Shared obj injection at -> %s", search_location);
                set_id_and_desc(id, new_result);
                set_other_info(search_for, new_result);
                set_issue_location(fi->location, new_result);
                set_issue_name(name, new_result);
                add_new_result_high(new_result, ar, cmdline);
                return true;
            }
        }
        else
        {
            if (mode == MISSING && search_shared_lib_in_dir(search_for, search_location))
            {
                return true;
            }
            if (mode == INJECT && is_folder_writable(search_location))
            {
                int id = 235;
                char name[MAXSIZE + 100];
                Result *new_result = create_new_issue();
                snprintf(name, MAXSIZE + 100, "Shared obj injection at -> %s", search_location);
                set_id_and_desc(id, new_result);
                set_other_info(search_for, new_result);
                set_issue_location(fi->location, new_result);
                set_issue_name(name, new_result);
                add_new_result_high(new_result, ar, cmdline);
                return true;
            }
        }
    }
    return false;
}

/** 
 * Walks the filesystem at location, looking for lib_name
 * @param libname the shared object that we're looking for 
 * @param location the root directory to walk
 * @return true if the shared object is found
 */
static bool search_shared_lib_in_dir(char *lib_name, char *location)
{
    DIR *dir;
    struct dirent *entry;
    char file_location[MAXSIZE];

    file_location[0] = '\0';

    dir = opendir(location);

    if (dir == NULL)
    {
        return false;
    }

    // printf("Searching for shared lib %s in location %s\n", lib_name, location);

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
        {
            if (strcmp(entry->d_name, location) == 0)
            {
                closedir(dir);
                return true;
            }
            if (entry->d_type & DT_DIR)
            {
                strncpy(file_location, location, MAXSIZE - 1);
                strcat(file_location, entry->d_name);
                strcat(file_location, "/");
                if (!search_shared_lib_in_dir(lib_name, file_location))
                {
                    continue;
                }
            }
        }
    }
    closedir(dir);
    return false;
}
