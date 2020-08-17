/*
    The idea of this scan is to look for files on the file system that 
    have strange permissions. For example the files UID/GUID does not 
    exist. Or global writable files in /root /boot etc. Because this 
    scan has the potential to produce loads of results it is disabled 
    in the quick scan mode and has to be enabled in the full scan mode. 

    1. Check system files are not global writable
    2. Check that files have a valid UID/GUID that exists
    3. Check that files owned in /home/user_n are onwed by user_n 
*/

#include "file_system.h"
#include "results.h"
#include "scan.h"
#include "error_logger.h"
#include "vector.h"
#include "main.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

/* ============================ CONST ============================== */

const char *FilesThatShouldNotBeWritable[] = {
    "/etc/passwd", "/etc/shadow", "/etc/fstab", "/etc/crypttab", "/etc/groups", "/etc/sudoers",
    "/etc/hosts", "/etc/host.conf", "/etc/hostname", "/etc/pacman.conf", "/etc/resolv.conf", "/etc/profile",
    "/etc/environment", "/etc/bashrc"};

const char *FilesThatShouldNotBeReadable[] = {"/etc/shadow", "/etc/crypttab", "/etc/sudoers"};

/* ============================ PROTOTYPES ============================== */

void permissions_scan(File_Info *fi, All_Results *ar, vec_void_t *users);
void writable_readable_config_files_scan(All_Results *ar);

static void check_global_write(All_Results *ar, File_Info *fi);
static void get_first_parent_dir(char *file_loc, char *buf);
static bool get_first_dir_that_protects_file(char *file_location, char *parent_dir_buf, All_Results *ar);
static void check_no_owner(All_Results *ar, File_Info *fi, vec_void_t *users);
static void check_uneven_permissions(File_Info *fi, All_Results *ar);
static bool check_uneven_permission_sets(bool r_high, bool w_high, bool x_high, bool r_low, bool w_low, bool x_low);
static void check_writable_sen_file(All_Results *ar, char *location);
static void check_readable_sen_file(All_Results *ar, char *location);

/* ============================ FUNCTIONS  ============================== */

/**
 * This scan will check the current file for common weak permissions
 * @param ar This is a struct containing enumy's results
 * @param fi This is the current file that is going to be scanned
 * @param users This is a struct containg the user data
 */
void permissions_scan(File_Info *fi, All_Results *ar, vec_void_t *users)
{
    check_global_write(ar, fi);
    check_no_owner(ar, fi, users);
    check_uneven_permissions(fi, ar);
}

/** 
 * This scan will check to see if any REALLY important files are 
 * world writable or world readable
 * @param ar This is a struct containing all of enumy's results
 */
void writable_readable_config_files_scan(All_Results *ar)
{
    int size_writable = sizeof(FilesThatShouldNotBeWritable) / sizeof(FilesThatShouldNotBeWritable[0]);
    int size_readable = sizeof(FilesThatShouldNotBeReadable) / sizeof(FilesThatShouldNotBeReadable[0]);

    for (int i = 0; i < size_writable; i++)
        check_writable_sen_file(ar, (char *)FilesThatShouldNotBeWritable[i]);

    for (int i = 0; i < size_readable; i++)
        check_readable_sen_file(ar, (char *)FilesThatShouldNotBeReadable[i]);
}

/**
 * This function will check the current file to see if it resides in a location 
 * that should be read only
 */
static void check_global_write(All_Results *ar, File_Info *fi)
{
    if (!has_global_write(fi))
        return;

    /* Check to see if the file is protected by any parent directories */
    char parent_buf[MAXSIZE] = {'\0'};
    char issue_buf[MAXSIZE + 50] = {'\0'};

    if (get_first_dir_that_protects_file(fi->location, parent_buf, ar))
    {
        /* The directory is protected */

        /* TODO HELP WANTED see */
        /* https://github.com/luke-goddard/enumy/issues/19 */

        // snprintf(issue_buf, (sizeof(issue_buf) - 1), "Found a protected world writable file in: %s", parent_buf);
        // struct stat stats;
        // if ((stat(parent_buf, &stats) != 0))
        // {
        //     log_error_errno_loc(ar, "Failed to stat directory", parent_buf, errno);
        //     printf("%i -> %i -> %s -> %i -> %s\n", LOW, AUDIT, fi->location, ar == NULL, issue_buf);
        //     add_issue(LOW, AUDIT, fi->location, ar, issue_buf, "ENUMY failed to stat the parent directory");
        //     return;
        // }
        // // John: getpwuid is not re-entrant. Using getpwuid_r should fix this issue.
        // struct passwd *data = getpwuid_r(stats.st_uid);
        // if (data == NULL)
        // {
        //     log_error_errno_loc(ar, "Failed to stat directory", parent_buf, errno);
        //     add_issue(LOW, AUDIT, fi->location, ar, issue_buf, "ENUMY failed to got the owner of the directory");
        //     return;
        // }
        add_issue(LOW, AUDIT, fi->location, ar, issue_buf, "");
        return;
    }

    /* Report global writable file that is NOT protected by parent directories */
    memset(parent_buf, '\0', sizeof(parent_buf));
    get_first_parent_dir(fi->location, parent_buf);
    snprintf(issue_buf, (sizeof(issue_buf) - 1), "Found an unprotected world writable file in: %s", parent_buf);
    add_issue(HIGH, AUDIT, fi->location, ar, issue_buf, "");
}

/**
 * This scan will check the current file to see a valid UID is attached to it
 * @param ar This is a struct containing enumy's results
 * @param fi This is the current file that is going to be scanned
 */
static void check_no_owner(All_Results *ar, File_Info *fi, vec_void_t *users)
{
    /* Found a valid UID */
    for (int i = 0; i < users->length; i++)
    {
        Parsed_Passwd_Line *current = users->data[i];
        if (current->uid == fi->stat->st_uid)
            return;
    }
    char issue_buf[MAXSIZE + 50] = {'\0'};
    snprintf(issue_buf, (sizeof(issue_buf) - 1), "Found a file with nonexistant GID: %d", fi->stat->st_gid);
    add_issue(MEDIUM, AUDIT, fi->location, ar, issue_buf, "");
}

/**
 * This function gets the first parent directory for a given file
 * so /tmp/test/1 would return /tmp/
 * @param file_loc location of the file to check 
 * @param buf location to store the result
 */
static void get_first_parent_dir(char *file_loc, char *buf)
{
    int file_path_size = strlen(file_loc);

    for (int i = 0; i < file_path_size; i++)
    {
        buf[i] = file_loc[i];

        /* break on second slash */
        if ((buf[i] == '/') && (i != 0))
            return;
    }
}

/**
 * A file might have global write enabled on it but a parent directory 
 * might not have the executable bit set, this means that you won't be able
 * to modify the file. 
 * @param file_locaiton location of the file to check 
 * @param parent_dir_buf Place to save the result 
 * @return True if the file has a protector else False
 */
static bool get_first_dir_that_protects_file(char *file_location, char *parent_dir_buf, All_Results *ar)
{
    int path_len = strlen(file_location);
    char current;

    for (int i = 0; i < path_len; i++)
    {
        current = file_location[i];
        parent_dir_buf[i] = current;

        if (current == '/')
        {
            struct stat stats;
            if (stat(parent_dir_buf, &stats) != 0)
            {
                log_error_errno_loc(ar, "Failed to stat directory", parent_dir_buf, errno);
                continue;
            }
            if (!(stats.st_mode & S_IXOTH))
            {
                parent_dir_buf[i + 1] = '\0';
                return true;
            }
        }
    }
    return false;
}

/**
 * This scan will check to see if any of
 * - Owner permission bits are less than group permission bits 
 * - Owner permission bits are less than other permission bits 
 * - Group permission bits are less than other permission bits 
 * @param fi The file we're scanning
 * @param ar enumy's results 
 */
static void check_uneven_permissions(File_Info *fi, All_Results *ar)
{
    /* OWNER */
    bool owner_read = ((1 << 8) & fi->stat->st_mode);
    bool owner_write = ((1 << 7) & fi->stat->st_mode);
    bool owner_execute = ((1 << 6) & fi->stat->st_mode);

    /* GROUP */
    bool group_read = (1 << 5) & fi->stat->st_mode;
    bool group_write = (1 << 4) & fi->stat->st_mode;
    bool group_execute = (1 << 3) & fi->stat->st_mode;

    /* OTHER */
    bool other_read = (1 << 2) & fi->stat->st_mode;
    bool other_write = (1 << 1) & fi->stat->st_mode;
    bool other_execute = (1 << 0) & fi->stat->st_mode;

    /* OWNER < GROUP */
    if (check_uneven_permission_sets(owner_read, owner_write, owner_execute, group_read, group_write, group_execute))
        add_issue(MEDIUM, CTF, fi->location, ar, "Group permissions are higher than Owner permissions", "");

    /* OWNER < OTHER */
    if (check_uneven_permission_sets(owner_read, owner_write, owner_execute, other_read, other_write, other_execute))
        add_issue(MEDIUM, CTF, fi->location, ar, "Other permissions are higher than Owner permissions", "");

    /* GROUP < OTHER */
    if (check_uneven_permission_sets(group_read, group_write, group_execute, other_read, other_write, other_execute))
        add_issue(MEDIUM, CTF, fi->location, ar, "Other permissions are higher than Group permissions", "");
}

/**
 *               | read | write | execute
 * owner         |  1   | 0     | 1
 * user          |  0   | 1     | 0
 * ========================================
 *    !owner     |  0   | 1     | 0
 * ========================================
 * !owner & user |  0   | 1     | 0
 * owner write is less than user write. 
 */
static bool check_uneven_permission_sets(bool r_high, bool w_high, bool x_high, bool r_low, bool w_low, bool x_low)
{
    return (
        (!r_high && r_low) ||
        (!w_high && w_low) ||
        (!x_high && x_low));
}

/**
 * This function will check the permissions on the at location 
 * and see if the current process has the ablity to write to that
 * file
 * @param ar all results 
 * @param location location of the file to test
 */
static void check_writable_sen_file(All_Results *ar, char *location)
{
    struct stat stats;

    /* Check location exists */
    if (!access(location, F_OK))
        return;

    /* Stat location */
    if (stat(location, &stats) != 0)
    {
        log_error_errno_loc(ar, "Failed to stat file", location, errno);
        return;
    }

    /* Check for global write */
    if (stats.st_mode & S_IWOTH)
        add_issue(HIGH, CTF, location, ar, "Important file is world writeable", "");

    /* Check if current non root users can write to fstab */
    else if (access(location, W_OK) && (getuid() != 0))
        add_issue(HIGH, CTF, location, ar, "Current user can write to important file", "");
}

/**
 * This function will check the permissions on the at location 
 * and see if the current process has the ablity to read to that
 * file
 * @param ar all results 
 * @param location location of the file to test
 */
static void check_readable_sen_file(All_Results *ar, char *location)
{
    struct stat fstab_stat;

    /* Checklocationfstab exists */
    if (!access(location, F_OK))
        return;

    /* Stat location */
    if (stat(location, &fstab_stat) != 0)
    {
        log_error_errno_loc(ar, "Failed to stat file", location, errno);
        return;
    }

    /* Check for global write */
    if (fstab_stat.st_mode & S_IROTH)
        add_issue(HIGH, CTF, location, ar, "Important file is readable writeable", "");

    /* Check if current non root users can write to fstab */
    else if (access(location, R_OK) && (getuid() != 0))
        add_issue(HIGH, CTF, location, ar, "Current user can read from very important file", "");
}
