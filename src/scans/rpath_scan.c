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
#include "error_logger.h"
#include "elf_parsing.h"
#include "debug.h"
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

/* ============================ DEFINES ============================== */

#define MISSING false /* State to find missing shared objects */
#define INJECT true   /* State to find injectable shared objects */

/* ============================ STRUCTS ============================== */

typedef struct Lib_Info
{
    Tag_Array *dt_needed;  /* All the shared libaries files names */
    Tag_Array *dt_rpath;   /* High precedence */
    Tag_Array *dt_runpath; /* Low precedence */
} Lib_Info;

/* ============================ PROTOTYPES ============================== */

int rpath_scan(File_Info *fi, All_Results *ar, Args *cmdline);

static Lib_Info *get_lib_info(Elf_File *elf);
static int test_missing_shared_libaries(Lib_Info *lib_info, File_Info *fi, All_Results *ar, Args *cmdline);
static void free_lib_info(Lib_Info *lib_info);
static bool search_shared_lib_in_dir(char *lib_name, char *location);
static bool search_for_injectable(char *search_for, Tag_Array *tag, char *origin, File_Info *fi, All_Results *all_results);
static bool search_dyn_path_for_missing(char *search_for, Tag_Array *tag, char *origin);
static bool search_dyn_path(char *search_for, Tag_Array *tag, char *origin, bool mode, File_Info *fi, All_Results *ar);

/* ============================ FUNCTIONS ============================== */

/**
 * The elf file format specifies that the names of shared objects required for the executable 
 * to be run should be stored in the dynamic section of the ELF file. This scan will try and parse 
 * the elf file to see if any of those shared objects are missing, writable. If the shared object 
 * is missing we can also check to see if the RPATH or RUNPATH is specified in the binary. There
 * is a small chance that this location is writable by the current user meaning that we can 
 * inject arbitrary code into a stub shared object and load that instead. If that ELF file is 
 * called by a root user/process then we can comprimise the entire system. 
 * @param fi This is the current file that's going to be scanned 
 * @param ar This is the structure that holds the link lists with the results 
 * @param args This is the runtime arguments needed for the scan
 */
int rpath_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;

    /* This scan is only run if specified at run time */
    if (cmdline->enabled_full_scans != true)
        return findings;

    /* Test to see if the file is really an elf */
    int arch = has_elf_magic_bytes(fi);
    if (
        (arch == NOT_ELF) ||
        (arch == 1 && sizeof(char *) != 4) ||
        (arch == 2 && sizeof(char *) != 8))
        return findings;

    /* Parse the elf file */
    Elf_File *elf = parse_elf(ar, fi);
    if (elf == NULL)
    {
        /* parse elf will log the error */
        return findings;
    }

    /* Parse the elf files dynamic section and parses the required shared objects needed */
    if (!elf_parse_dynamic_sections(elf))
    {
        log_warn_loc(ar, "ELF file does not have a dynamic section", fi->location);
        goto CLOSE_ELF;
    }

    /* Run the actual test */
    Lib_Info *lib_info = get_lib_info(elf);
    findings += test_missing_shared_libaries(lib_info, fi, ar, cmdline);
    free_lib_info(lib_info);

CLOSE_ELF:
    close_elf(elf, fi);
    return findings;
}

/* ============================ STATIC FUNCTIONS ============================== */

/**
 * Takes an Elf_File and then searches the dynamic section for 3 tags, DT_NEEDED
 * DT_RPATH and DT_RUNPATH. Creates a struct containing the results
 * @param elf pointer to an Elf_File that has allready been parsed
 * @return a pointer to results
 */
static Lib_Info *get_lib_info(Elf_File *elf)
{
    /* Allocate struct to store results */
    Lib_Info *lib_info = malloc(sizeof(Lib_Info));
    if (lib_info == NULL)
    {
        log_fatal("Failed to allocate memory when trying to get lib info\n");
        exit(EXIT_FAILURE);
    }

    /* Parse the elf for DT_NEEDED, DT_RPATH, DT_RUNPATH */
    lib_info->dt_needed = search_dynamic_for_value(elf, DT_NEEDED);
    lib_info->dt_rpath = search_dynamic_for_value(elf, DT_RPATH);
    lib_info->dt_runpath = search_dynamic_for_value(elf, DT_RUNPATH);

    return lib_info;
}

static void free_lib_info(Lib_Info *lib_info)
{
    free(lib_info->dt_needed);
    free(lib_info->dt_rpath);
    free(lib_info->dt_runpath);
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

    /* Does not need any shared libs */
    if (lib_info->dt_needed == NULL)
        return findings;

    /* Location of the binary */
    origin = get_dir_name(fi->location);
    if (origin == NULL)
    {
        log_warn_loc(ar, "Failed to get $ORIGIN's real location", fi->location);
        return findings;
    }

    strcat(origin, "/");

    /* Search for every DT_NEEDED dependency */
    for (int i = 0; i < lib_info->dt_needed[0].size; i++)
    {
        if (strcasestr(lib_info->dt_needed[i].tag_value, ".so") == NULL)
        {
            log_error_loc(ar, "Failed to correctly parse DT_NEEDED, or the elf file is corrupted", fi->location);
            continue;
        }

        /* check rpath */
        if (search_dyn_path_for_missing(lib_info->dt_needed[i].tag_value, lib_info->dt_rpath, origin))
            continue;

        /* It's not in rpath, do we have control to anwhere in rpath */
        if (search_for_injectable(lib_info->dt_needed[i].tag_value, lib_info->dt_rpath, origin, fi, ar))
            break;

        /* Check normal shared objects in /usr/lib etc */
        if (test_if_standard_shared_object(cmdline->valid_shared_libs, lib_info->dt_needed[i].tag_value))
            continue;

        /* check run_path */
        if (search_dyn_path_for_missing(lib_info->dt_needed[i].tag_value, lib_info->dt_runpath, origin))
            continue;

        /* It's not in rpath, do we have control to anwhere in rpath */
        if (search_for_injectable(lib_info->dt_needed[i].tag_value, lib_info->dt_runpath, origin, fi, ar))
            break;

        char name[MAXSIZE + 100];
        snprintf(name, MAXSIZE, "Missing shared libary %s", lib_info->dt_needed[i].tag_value);
        add_issue(INFO, NEVER_PRINT, fi->location, ar, name, "");
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
    return search_dyn_path(search_for, tag, origin, MISSING, NULL, NULL);
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
 * @return true if an injectable location has been found
 */
static bool search_for_injectable(char *search_for, Tag_Array *tag, char *origin, File_Info *fi, All_Results *all_results)
{
    return search_dyn_path(search_for, tag, origin, INJECT, fi, all_results);
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
 * @return true if shared object has been found
 */
static bool search_dyn_path(char *search_for, Tag_Array *tag, char *origin, bool mode,
                            File_Info *fi, All_Results *ar)
{
    char search_location[MAXSIZE] = {'\0'};

    char *current_rpath = NULL;
    char current_character;
    int buf_copy_loc = 0;
    int tag_size = 0;
    bool inloop = true;
    char shared_issue_name[MAXSIZE + 100];
    char suid_issue_name[MAXSIZE + 100];
    int y = 0;

    if (tag == NULL)
        return false;

    /* ========================== TODO ============================== */
    /*
        From testing I found the following edge case;
        
        $ readelf -d /opt/minecraft-launcher/minecraft-launcher | grep RPATH
            0x000000000000000f (RPATH)              Library rpath: [.:$ORIGIN/]

        1. How does the linker handle "." will have to look at the source code?
        2. $ORIGIN/ != $ORIGIN is this another potential way of specifying rpath?  
    */
    /* ========================== TODO ============================== */

    /* Itterate through each path tag found in binary */
    for (int i = 0; i < tag[0].size; i++)
    {
        current_rpath = tag[i].tag_value;
        buf_copy_loc = 0;
        tag_size = (int)strlen(current_rpath);

        /* Itterate through each character in a tag (tokenized with ":") */
        for (y = 0; y < tag_size; y++)
        {
            current_character = current_rpath[y];

            /* End of an entry is identified with a ':' */
            if (current_character == ':')
            {

                search_location[buf_copy_loc] = '\0';
                buf_copy_loc = 0;

                inloop = true;

            TEST:
                /* Change issue names */
                memset(shared_issue_name, '\0', MAXSIZE + 100);
                memset(suid_issue_name, '\0', MAXSIZE + 100);
                snprintf(shared_issue_name, MAXSIZE + 100, "Shared obj injection at -> %s", search_location);
                snprintf(suid_issue_name, MAXSIZE + 100, "SUID binary with $ORIGIN -> %s", search_location);

                if (strcmp("$ORIGIN", search_location) == 0)
                {
                    /* SUID binary with $ORIGIN is not good */
                    if (fi != NULL && has_suid(fi))
                        add_issue(HIGH, CTF, fi->location, ar, suid_issue_name, search_for);

                    /* Check to see if any missing shared objects */
                    if (mode == MISSING && search_shared_lib_in_dir(search_for, origin))
                        return true;

                    /* Missing shared objects could be placed in $ORIGIN */
                    if (fi != NULL && mode == INJECT && is_folder_writable(search_location))
                        add_issue(HIGH, CTF, fi->location, ar, shared_issue_name, search_for);
                }
                else
                {
                    if (mode == MISSING && search_shared_lib_in_dir(search_for, search_location))
                        return true;

                    /* Can we inject any malicious shared objects */
                    if (mode == INJECT && is_folder_writable(search_location))
                        add_issue(HIGH, CTF, fi->location, ar, shared_issue_name, search_for);
                }
                search_location[buf_copy_loc] = '\0';
                if (!inloop)
                    return false;
            }
            /* Tag is not completed carry on parsing */
            else
            {
                search_location[buf_copy_loc] = current_character;
                buf_copy_loc++;
            }
        }
    }
    /* Test the last tag as this one wont end in a ':' */
    inloop = false;
    goto TEST;
}

/** 
 * list the filesystem at location, looking for lib_name (Non recursive)
 * @param libname the shared object that we're looking for 
 * @param location the root directory to walk
 * @return true if the shared object is found
 */
static bool search_shared_lib_in_dir(char *lib_name, char *location)
{
    DIR *dir;
    struct dirent *entry;

    /* Open the directory to search */
    dir = opendir(location);
    if (dir == NULL)
        return false;

    /* List the directory */
    while ((entry = readdir(dir)) != NULL)
    {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
        {
            /* Shared object found */
            if (strcmp(entry->d_name, lib_name) == 0)
            {
                closedir(dir);
                return true;
            }
        }
    }

    /* Options exhausted, *.so not found */
    closedir(dir);
    return false;
}