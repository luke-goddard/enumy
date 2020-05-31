/*
    This file is used to find out where the ld will look for share objects at 
    run time. We can use this list to find out if any executables have injectable 
    shared objects. This is used in conjunction with the RPATH scan
*/

#include "file_system.h"
#include "vector.h"
#include "debug.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <ctype.h>

/* ============================ DEFINES ============================== */

#define SHARED_LIBS_CONF "/etc/ld.so.conf.d/"

/* ============================ PROTOTYPES ============================== */

bool find_shared_libs(vec_str_t *shared_lib_vec);
bool test_if_standard_shared_object(vec_str_t *shared_libs, char *new_shared_lib);
void free_shared_libs(vec_str_t *v);

static void walk(char *location, vec_str_t *v);
static bool read_file(char *location, vec_str_t *v);

/* ============================ FUNCTIONS ============================== */

/**
 * This function will find where ld.so searches for shared objects and 
 * then walk through all of those search locations. When a shared object 
 * is found we will add the full path to the vector
 * @param shared_lib_vec Uninitilized pointer to a vector to store results 
 * @return Returns false if something went wrong and True if everything went well
 */
bool find_shared_libs(vec_str_t *shared_lib_vec)
{

    vec_str_t ld_confd_vec;
    vec_str_t ld_confd_res_vec;

    /* Initilize the vectors */
    vec_init(&ld_confd_vec);
    vec_init(&ld_confd_res_vec);
    vec_init(shared_lib_vec);

    /* Finds files in SHARED_LIBS_CONFS */
    walk(SHARED_LIBS_CONF, &ld_confd_vec);

    /* Find all lines in all files in SHARED_LIBS_CONF and place them in ld_confd_res_vec*/
    for (int i = 0; i < ld_confd_vec.length; i++)
    {
        if (!read_file(ld_confd_vec.data[i], &ld_confd_res_vec))
            DEBUG_PRINT("Failed to read file at location -> %s\n", ld_confd_vec.data[i]);
    }

    /* Walk all possible so directories to find all standard shared objects */
    for (int i = 0; i < ld_confd_res_vec.length; i++)
    {
        char *walk_location = ld_confd_res_vec.data[i];
        if (access(walk_location, R_OK) != 0)
        {
            DEBUG_PRINT("Failed finding the shared objects in -> %s\n", walk_location);
            continue;
        }
        walk(walk_location, shared_lib_vec);
    }

    walk("/usr/lib/", shared_lib_vec);
    walk("/usr/lib32/", shared_lib_vec);
    walk("/usr/lib64/", shared_lib_vec);

    for (int i = 0; i < ld_confd_vec.length; i++)
        free(ld_confd_vec.data[i]);

    for (int i = 0; i < ld_confd_res_vec.length; i++)
        free(ld_confd_res_vec.data[i]);

    vec_deinit(&ld_confd_vec);
    vec_deinit(&ld_confd_res_vec);

    return true;
}

/**
 * Given a populated vector containing shared object full path locations 
 * this function will search through the vector to see if the new_shared_lib 
 * exists inside of the vector 
 * @param shared_libs_vec This is the vector to itterate through
 * @param new_shared_lib This is the full path of the file that we want to search for 
 * @return True if the new_shared_lib was found inside of the shared_libs vector 
 */
bool test_if_standard_shared_object(vec_str_t *shared_libs, char *new_shared_lib)
{
    for (int i = 0; i < shared_libs->length; i++)
    {
        char *current_shared = shared_libs->data[i];
        char *current_shared_base_name = get_file_name(current_shared);
        if (strcmp(current_shared_base_name, new_shared_lib) == 0)
            return true;
    }
    return false;
}

/**
 * Given a vector this function will deallocate the memeory for the vector
 * @param v This is the vector to free
 */
void free_shared_libs(vec_str_t *v)
{
    for (int i = 0; i < v->length; i++)
        free(v->data[i]);

    vec_deinit(v);
}

/* ============================ STATIC FUNCTIONS ============================== */

/* ============================ TODO ============================== */
/* Header                                                           */
/* ============================ TODO ============================== */
static void walk(char *location, vec_str_t *v)
{
    /* ============================ TODO ============================== */
    /*  Walk can fail we should handle the return value */
    /* ============================ TODO ============================== */

    DIR *dir;
    struct dirent *entry;
    char file_location[MAXSIZE];

    file_location[0] = '\0';

    dir = opendir(location);

    if (dir == NULL)
        return;

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
        {

            /* ============================ TODO ============================== */
            /*  Buffer overflow possible?                                       */
            /* ============================ TODO ============================== */

            if (entry->d_type & DT_REG)
            {
                /* Ignore none shared objects */
                if (strstr(entry->d_name, ".so") == NULL)
                    continue;
                char *new_location = malloc(sizeof(char) * MAXSIZE);
                memset(new_location, '\0', sizeof(char) * MAXSIZE);
                strncpy(new_location, location, MAXSIZE - 1);
                strcat(new_location, entry->d_name);
                vec_push(v, new_location);
            }
            if (entry->d_type & DT_DIR)
            {
                strncpy(file_location, location, MAXSIZE - 1);
                strcat(file_location, entry->d_name);
                strcat(file_location, "/");
                walk(file_location, v);
            }
        }
    }
    closedir(dir);
}

/* ============================ TODO ============================== */
/* Header                                                           */
/* ============================ TODO ============================== */
static bool read_file(char *location, vec_str_t *v)
{
    char line[MAXSIZE] = {'\0'};
    FILE *file = fopen(location, "r");

    if (file == NULL)
    {
        DEBUG_PRINT("Failed to open potential shared lib at location -> %s\n", location);
        return false;
    }

    /* ============================ TODO ============================== */
    /*  If line is MAXSIZE or longer, new_line is unterminated. */
    /* Need to do that yourself. Or is fgets ok? Need to check. */
    /* ============================ TODO ============================== */
    while (fgets(line, sizeof(line), file))
    {

        /* ============================ TODO ============================== */
        /*  Malloc inside of for loop could be improved                     */
        /*  Return value not checked                                        */
        /*  Ignore lines that start with a comment                          */
        /* ============================ TODO ============================== */

        char *new_line = malloc(MAXSIZE + 1);
        strncpy(new_line, line, MAXSIZE);

        if (strlen(new_line) > 2 && new_line[strlen(new_line) - 1] == '\n')
            new_line[strlen(new_line) - 1] = '/';

        vec_push(v, new_line);
        memset(line, '\0', sizeof(line));
    }
    fclose(file);
    return true;
}
