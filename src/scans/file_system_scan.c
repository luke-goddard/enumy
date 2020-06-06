/*
                    Check that directories are mounted in different locations 
    HELP WANTED -   Check for luks encryption
    HELP WANTED -   Checking LVM Volume Groups
                    Checking /etc/fstab file permissions
    TODO            Checking Linux EXT2, EXT3, EXT4 file systems
    TODO            Checking Linux XFS file systems
    TODO            Check swap mount options
    TODO            Check proc mount options
    TODO            Check for sticky bit on /tmp
    TODO            Check for sticky bit on /var/tmp
    TODO            Search for files within /tmp which are older than 3 months
    HELP WANTED -   Checking Linux root file system ACL support
    TODO            Check / mount options for Linux
    TODO            Bind mount the /var/tmp directory to /tmp
    TODO            Check /var/tmp is mounted to /tmp
    TODO            Disable mounting of some filesystems
    https://github.com/CISOfy/lynis/blob/ce3c80b44f418e28503e1aecaeb87c170d0c811c/include/tests_filesystems
*/

#include "results.h"
#include "file_system.h"
#include "error_logger.h"
#include "vector.h"

#include "errno.h"
#include "string.h"
#include "stdio.h"

/* ============================ CONSTS  ============================== */

const char *ProcMountLoc = "/proc/mounts";
const char *FstabLoc = "/proc/mounts";

/* ============================ STRUCTS  ============================== */

typedef struct Proc_Mount
{
    char fs_spec[MAXSIZE];    /* Block device name */
    char fs_file[MAXSIZE];    /* This is the mount point */
    char fs_vfstype[MAXSIZE]; /* Type of file system */
    char fs_mntops[MAXSIZE];  /* mount point options */
    char fs_freq[MAXSIZE];    /* used by dump(8) */
    char fs_passno[MAXSIZE];  /*This field is used by fsck(8) */
} Proc_Mount;

/* ============================ PROTOTYPES ============================== */

void file_system_scan(All_Results *ar);

static vec_void_t *parse_proc_mounts(All_Results *ar);
static void check_mount_points_are_seperate(All_Results *ar, vec_void_t *mounts);
static void check_main_mount_points_are_encrypted();

/* ============================ FUNCTIONS ============================== */

/**
 * This scan will check what security is in place for mounted file systems
 * Common security practice is to have encrypted mount points for each area
 * read only mounts and addtional parameters set to prevent an intruder from 
 * gaining further access
 * @param ar A structure containing enumy's results
 */
void file_system_scan(All_Results *ar)
{
    vec_void_t *mounts = parse_proc_mounts(ar);

    check_mount_points_are_seperate(ar, mounts);
    check_main_mount_points_are_encrypted();

    /* Deallocate the memory */
    for (int i = 0; i < mounts->length; i++)
        free(mounts->data[i]);

    vec_deinit(mounts);
    free(mounts);
}

static vec_void_t *parse_proc_mounts(All_Results *ar)
{
    char current_line[MAXSIZE] = {'\0'};
    char *dest;

    /* Open /proc/mounts */
    FILE *fp = fopen(ProcMountLoc, "r");
    if (fp == NULL)
    {
        log_error_errno_loc(ar, "Failed to open proc mount", (char *)ProcMountLoc, errno);
        return NULL;
    }

    /* Allocate memory for results */
    vec_void_t *mount_point_vec = (vec_void_t *)malloc(sizeof(vec_void_t));
    if (mount_point_vec == NULL)
    {
        fclose(fp);
        log_fatal_errno("Failled to allocate memory for mount point vector", errno);
        exit(EXIT_FAILURE);
        return NULL;
    }
    vec_init(mount_point_vec);

    /* Loop through all the lines */
    while (fgets(current_line, sizeof current_line, fp))
    {
        char *token = strtok(current_line, " ");
        int pos = 0;

        /* Allocate memory for the new struct */
        Proc_Mount *current_mount = (Proc_Mount *)malloc(sizeof(Proc_Mount));
        if (current_mount == NULL)
        {
            fclose(fp);
            log_fatal_errno("Failled to allocate memory for current mount point", errno);
            exit(EXIT_FAILURE);
        }

        /* Parse the line */
        while (token != NULL)
        {
            if (pos == 0)
                dest = current_mount->fs_spec;
            else if (pos == 1)
                dest = current_mount->fs_file;
            else if (pos == 2)
                dest = current_mount->fs_vfstype;
            else if (pos == 3)
                dest = current_mount->fs_mntops;
            else if (pos == 4)
                dest = current_mount->fs_freq;
            else if (pos == 5)
                dest = current_mount->fs_passno;
            else
                goto BAD_LINE;

            if (strlen(token) >= MAXSIZE - 1)
                goto BAD_LINE;

            strncpy(dest, token, MAXSIZE - 1);

            token = strtok(NULL, " ");
            pos++;
        }
        memset(current_line, '\0', sizeof(current_line));
        if (pos != 6)
            goto BAD_LINE;

        vec_push(mount_point_vec, current_mount);
        continue;
    BAD_LINE:
        free(current_mount);
        log_error(ar, "Failed to parse /proc/mount");
    }

    fclose(fp);
    return mount_point_vec;
}

/**
 * Checks to see if the different mount points are seperate from "/"
 * /tmp /var/ /home 
 * Users should not be able to fill their home directory or temporary directory and creating a Denial of Service
 * @param ar This is the struct containing enumy's results 
 */
static void check_mount_points_are_seperate(All_Results *ar, vec_void_t *mounts)
{
    bool var, home, tmp;
    var = home = tmp = false;

    /* Loop through all mount points */
    for (int i = 0; i < mounts->length; i++)
    {
        Proc_Mount *current_mount = (Proc_Mount *)mounts->data[i];
        if ((strcmp(current_mount->fs_file, "/tmp") == 0) || (strcmp(current_mount->fs_file, "/tmp/") == 0))
            tmp = true;

        if ((strcmp(current_mount->fs_file, "/home") == 0) || (strcmp(current_mount->fs_file, "/home/") == 0))
            home = true;

        if ((strcmp(current_mount->fs_file, "/var") == 0) || (strcmp(current_mount->fs_file, "/var/") == 0))
            var = true;
    }

    if (!tmp)
        add_issue(MEDIUM, AUDIT, "", ar, "/tmp should have a mount point different to /", "");
    if (!home)
        add_issue(MEDIUM, AUDIT, "", ar, "/home/ should have a mount point different to /", "");
    if (!var)
        add_issue(MEDIUM, AUDIT, "", ar, "/var should have a mount point different to /", "");
}

/**
 * HELP WANTED
 * The idea of this scan is to test if mount points such as / are encrypted
 * Think you can help? https://github.com/luke-goddard/enumy/issues/18 
 */
static void check_main_mount_points_are_encrypted()
{
}