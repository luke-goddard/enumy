/*
    Most scans will require a file, for example a scan could test to see if a file 
    is SUID and world writable. This means that we need a way to populate a list of 
    files and some basic information about them. These functions try and solve that. 

    The filesystem is walked, when a new file is found it is added to a threadpool. 
    The threadpool is the entry point to run scans that require a file as mentioned
    above. The File_Info struct is used extensivly throughout the program. 

    This header also defines some useful functions that can be utilized by the scans.
    These functions relate to File_Info and can perform common operations such as 
    has_global_write()

    This file also contains a few functions that relate to shared libaries. 
*/

#pragma once

#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <unistd.h>
#include <dirent.h>

#include "results.h"
#include "vector.h"

/* ============================ DEFINES ============================== */

#define MAX_FILE_SIZE 4096    /* Paths can be longer than this on LINUX, but it's unlikely                 */
#define MAX_EXTENSION_SIZE 16 /* Truncated extensions wont effect scans because we're only                 */
                              /* looking for a small subset of prefined extensions less than 16 bytes long */

/* ============================ STRUCTS ============================== */

/* This struct holds basic information about a file found by walking the file system */
typedef struct File_Info
{
    char location[MAX_FILE_SIZE];       /* Full path location to the file   */
    char name[MAX_FILE_SIZE];           /* The files basename               */
    char extension[MAX_EXTENSION_SIZE]; /* The files extension              */
    struct stat *stat;                  /* Pointer to a stat buffer         */
} File_Info;

/* This struct holds the arguments required for the thread to run scans */
typedef struct Thread_Pool_Args
{
    char file_location[MAXSIZE]; /* Location of the file to run the scan against */
    char file_name[MAXSIZE];     /* Name of the file to run the scan agasinst */
    All_Results *all_results;    /* Struct containing a linked list of issues found */
    Args *cmdline;               /* Runtime arguments specified by user */
    vec_void_t *users;           /* Parsed /etc/passwd file */
} Thread_Pool_Args;

/* This struct holds the parsed /etc/passwd contents */
typedef struct Parsed_Passwd_Line
{
    char username[MAXSIZE]; /* Username of the account */
    char password[MAXSIZE]; /* Password for the account */
    char home[MAXSIZE];     /* Home directory for the account */
    char shell[MAXSIZE];    /* Command to run at login for the accoutn */
    unsigned int uid;       /* UID for the account */
    unsigned int gid;       /* GID for the account */
} Parsed_Passwd_Line;

/* ============================ PROTOTYPES ============================== */

/**
 * This function will recursivily walk the file system at location entry_location
 * When a new found is found this function will pass the file location to a the thread
 * pool where that thread will run scans against the current file. 
 * @param entry_location This is the root location to walk the file system 
 * @param all_results This is the struct with linked lists containing issues enumy's found
 * @param cmdline This is a list of run time arguments specified by the userr
 */
void walk_file_system(char *entry_location, All_Results *all_results, Args *cmdline, vec_void_t *users);

/** Returns the d_type field if present i.e. not DT_UNKNOWN, otherwise, the equivilant is read from lstat.
 *  @param entry the direct entry to read from.
 *  @param location the directory that the entry is contained in. _NOT_ the path of the file itself.
 */
unsigned char get_d_type(struct dirent* entry, const char* location);

/* ============================ File_Info Functions  ============================== */

/**
 * Tests to see if other write is enabled 
 * @param fi this is the current file that's being scanned 
 */
bool has_global_write(File_Info *fi);

/**
 * Tests to see if other read is enabled 
 * @param fi this is the current file that's being scanned 
 */
bool has_global_read(File_Info *fi);

/**
 * Tests to see if other execute is enabled 
 * @param fi this is the current file that's being scanned 
 */
bool has_global_execute(File_Info *fi);

/**
 * Tests to see if group write is enabled 
 * @param fi this is the current file that's being scanned 
 */
bool has_group_write(File_Info *fi);

/**
 * Tests to see if group execute is enabled 
 * @param fi this is the current file that's being scanned 
 */
bool has_group_execute(File_Info *fi);

/**
 * Tests to see if the group or other can execute the file 
 * @param fi this is the current file that's being scanned 
 */
bool has_executable(File_Info *fi);

/**
 * Tests to see if the current file has SUID bit enabled 
 * @param fi this is the current file that's being scanned 
 */
bool has_suid(File_Info *fi);

/**
 * Tests to see if the current file has GUID bit enabled
 * @param fi this is the current file that's being scanned 
 */
bool has_guid(File_Info *fi);

/**
 * Tests to see if the current file has a matching extension
 * @param fi this is the current file that's being scanned 
 * @param extension this is the extension to check against
 */
bool has_extension(File_Info *fi, char *extension);

/**
 * Tests to see if the file is readable by the current process 
 * @param fi this is the current file that's being scanned 
 */
bool can_read(File_Info *fi);

/* ============================ Shared Lib Functions  ============================== */

/**
 * This function will find where ld.so searches for shared objects and 
 * then walk through all of those search locations. When a shared object 
 * is found we will add the full path to the vector
 * @param shared_lib_vector Uninitilized pointer to a vector to store results 
 * @return Returns false if something went wrong and True if everything went well
 */
bool find_shared_libs(vec_str_t *shared_lib_vec);

/**
 * Given a populated vector containing shared object full path locations 
 * this function will search through the vector to see if the new_shared_lib 
 * exists inside of the vector 
 * @param shared_libs_vec This is the vector to itterate through
 * @param new_shared_lib This is the full path of the file that we want to search for 
 * @return True if the new_shared_lib was found inside of the shared_libs vector 
 */
bool test_if_standard_shared_object(vec_str_t *shared_libs_vec, char *new_shared_lib);

/**
 * Given a vector this function will deallocate the memeory for the vector
 * @param v This is the vector to free
 */
void free_shared_libs(vec_str_t *v);

/* ============================ MISC Functions  ============================== */

/**
 * Given a full path this function returns the file path 
 * DONT forget to free the returned pointer
 * @param full_path the files full path
 * @return a heap pointer containing the file's name
 */
char *get_file_name(char *full_path);
/**
 * Given a full path this function will return all the files parent directorys 
 * DONT forget to free the returned pointer 
 * @param full_path the files full path 
 * @return a heap pointer containing the files's directory name 
 */
char *get_dir_name(char *full_path);

/**
* Get the file extension the "." is not saved and an extension
* abc.tar.gz would return .gz not .tar.gz
* The extensions is saved in lowercase
* @param buffer location to save the file extension
* @param f_name the files name 
*/
void get_file_extension(char *buf, char *f_name);

/**
 * Given a directory returns true if the current process 
 * can write to that directory 
 * @param path location to test if writable
 */
bool is_folder_writable(char *path);
