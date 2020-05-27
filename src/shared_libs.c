/*
    This file is used to find out where the ld will look for share objects at 
    run time. We can use this list to find out if any executables have injectable 
    shared objects. This is used in conjunction with the RPATH scan
*/

#include "file_system.h"
#include "utils.h"
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

Vector *find_shared_libs();
bool test_if_standard_shared_object(Vector *shared_libs, char *new_shared_lib);
void free_shared_libs(Vector *v);

static void walk(char *location, Vector *v);
static bool read_file(char *location, Vector *v);

/* ============================ FUNCTIONS ============================== */

Vector *find_shared_libs()
{
    char *walk_location;

    Vector ld_confd_vec;
    Vector ld_confd_res_vec;
    Vector *shared_libs = malloc(sizeof(Vector)); // contains the list of shared objects that have been found

    vector_init(&ld_confd_vec);
    vector_init(&ld_confd_res_vec);
    vector_init(shared_libs);

    // Finds files in SHARED_LIBS_CONFS
    walk(SHARED_LIBS_CONF, &ld_confd_vec);

    // Find all lines in all files in SHARED_LIBS_CONF
    for (int i = 0; i < vector_total(&ld_confd_vec); i++)
    {
        read_file((char *)vector_get(&ld_confd_vec, i), &ld_confd_res_vec);
        free(vector_get(&ld_confd_vec, i));
    }

    for (int i = 0; i < vector_total(&ld_confd_res_vec); i++)
    {
        walk_location = vector_get(&ld_confd_res_vec, i);
        if (access(walk_location, R_OK) != 0)
        {
            DEBUG_PRINT("Failed finding shared objects in -> %s\n", walk_location);
            continue;
        }
        walk(walk_location, shared_libs);
        free(vector_get(&ld_confd_res_vec, i));
    }

    walk("/usr/lib/", shared_libs);
    walk("/usr/lib32/", shared_libs);
    walk("/usr/lib64/", shared_libs);

    vector_free(&ld_confd_vec);
    vector_free(&ld_confd_res_vec);

    return shared_libs;
}

bool test_if_standard_shared_object(Vector *shared_libs, char *new_shared_lib)
{
    char *current_shared;
    char *current_shared_base_name;

    for (int i = 0; i < vector_total(shared_libs); i++)
    {
        current_shared = vector_get(shared_libs, i);
        current_shared_base_name = get_file_name(current_shared);
        if (strcmp(current_shared_base_name, new_shared_lib) == 0)
        {
            free(current_shared_base_name);
            return true;
        }
        free(current_shared_base_name);
    }
    return false;
}

void free_shared_libs(Vector *v)
{
    for (int i = 0; i < vector_total(v); i++)
        free(vector_get(v, i));

    free(v);
}

/* ============================ STATIC FUNCTIONS ============================== */

static void walk(char *location, Vector *v)
{
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

            if (entry->d_type & DT_REG)
            {
                char *new_location = malloc(sizeof(char) * MAXSIZE);
                memset(new_location, '\0', sizeof(char) * MAXSIZE);
                strncpy(new_location, location, MAXSIZE - 1);
                strcat(new_location, entry->d_name);
                vector_add(v, new_location);
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

static bool read_file(char *location, Vector *v)
{
    char line[MAXSIZE];
    FILE *file = fopen(location, "r");

    if (file == NULL)
    {
        DEBUG_PRINT("Failed to open potential shared lib at location -> %s\n", location);
        return false;
    }
    while (fgets(line, sizeof(line), file))
    {
        char *new_line = malloc(MAXSIZE);
        strncpy(new_line, line, MAXSIZE - 1);

        if (strlen(new_line) > 2 && new_line[strlen(new_line) - 1] == '\n')
            new_line[strlen(new_line) - 1] = '/';

        vector_add(v, new_line);
    }
    fclose(file);
    return true;
}
