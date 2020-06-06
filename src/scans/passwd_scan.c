/*
    The passwd scan is used to parse /etc/passwd, once parsed we can 
    run a few basic checks (seen below). And we use this parsed information
    in other scans.

    1. Report all users with UID 0
    2. Report all users with GID 0 
    3. Report all users with out /nologin
    3. Report all users with invalid home directory
    4. Report all users where the login shell has weak permissions
    5. Check to see if password hashes are stored here
*/

#include "file_system.h"
#include "results.h"
#include "scan.h"
#include "error_logger.h"
#include "main.h"
#include "vector.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

/* ============================ PROTOTYPES ============================== */

char *PasswdLoc = "/etc/passwd";

/* ============================ PROTOTYPES ============================== */

vec_void_t *passwd_scan(All_Results *ar);
void free_users(vec_void_t *users);

static void check_uid(Parsed_Passwd_Line *current, All_Results *ar);
static void check_gid(Parsed_Passwd_Line *current, All_Results *ar);
static void check_login_shell(Parsed_Passwd_Line *current, All_Results *ar);
static void check_home_exists(Parsed_Passwd_Line *current, All_Results *ar);
static void check_password_hashes(Parsed_Passwd_Line *current, All_Results *ar);

static vec_void_t *parse_etc_passwd(All_Results *ar);
static bool parse_etc_passwd_line(char *current_line, Parsed_Passwd_Line *storage, All_Results *ar);
static bool parse_int(char *s, unsigned int *i_ptr);

/* ============================ FUNCTIONS  ============================== */

/**
 * This function will read and parse the /etc/passwd file and then run various 
 * scans against the contents of this file.
 * @param ar Enumy's results struct
 * @return Returns a vector containing pointers to Parsed_Passwd_line
 */
vec_void_t *passwd_scan(All_Results *ar)
{
    /* Parse /etc/passwd */
    vec_void_t *contents = parse_etc_passwd(ar);
    if (!contents)
        return NULL;

    /* Loop threw each parsed /etc/passwd entry */
    for (int i = 0; i < contents->length; i++)
    {
        check_uid((Parsed_Passwd_Line *)contents->data[i], ar);
        check_gid((Parsed_Passwd_Line *)contents->data[i], ar);
        check_login_shell((Parsed_Passwd_Line *)contents->data[i], ar);
        check_home_exists((Parsed_Passwd_Line *)contents->data[i], ar);
        check_password_hashes((Parsed_Passwd_Line *)contents->data[i], ar);
    }

    return contents;
}

/**
 * Deallocates the memory used by calling passwd_scan
 * @param users vector containing pointers to Parsed_Passwd_line
 */
void free_users(vec_void_t *users)
{
    for (int i = 0; i < users->length; i++)
        free(users->data[i]);

    vec_deinit(users);
}

/* ============================ STATIC FUNCTIONS  ============================== */

/* ============================ SCAN FUNCTIONS  ============================== */

/**
 * This function finds root users with UID root 
 * @param current This is the current /etc/passwd line that has been parsed
 * @param ar enumy's results
 */
static void check_uid(Parsed_Passwd_Line *current, All_Results *ar)
{
    if (current->uid == 0)
    {
        char buf[MAXSIZE * 2];
        snprintf(buf, (MAXSIZE * 2) - 1, "Found an new root user with UID 0: %s", current->username);
        add_issue(INFO, CTF, PasswdLoc, ar, buf, "");
    }
}

/**
 * This function finds root users with GID root 
 * @param current This is the current /etc/passwd line that has been parsed
 * @param ar enumy's results
 */
static void check_gid(Parsed_Passwd_Line *current, All_Results *ar)
{
    if (current->gid == 0)
    {
        char buf[MAXSIZE * 2];
        snprintf(buf, (MAXSIZE * 2) - 1, "Found an new root user with GID 0: %s", current->username);
        add_issue(INFO, CTF, PasswdLoc, ar, buf, "");
    }
}

/**
 * This function find users that can be logged into, shells that don't exist
 * and shells that are writable
 * @param current This is the current /etc/passwd line that has been parsed
 * @param ar enumy's results
 */
static void check_login_shell(Parsed_Passwd_Line *current, All_Results *ar)
{
    /* Check if we can login */
    if (strstr(current->shell, "nologin") != NULL)
        return;

    char buf[MAXSIZE * 2];
    snprintf(buf, (MAXSIZE * 2) - 1, "Found an new user that can be logged into: %s", current->username);
    add_issue(INFO, CTF, PasswdLoc, ar, buf, "");

    /* Check if the file exsts */
    if (access(current->home, F_OK) == -1)
    {
        add_issue(HIGH, CTF, current->shell, ar, "Found a new user that can be logged into a shell that does not exist", "");
        return;
    }

    /* allocate memory for stat buffer */
    struct stat *stat_buf = malloc(sizeof(struct stat));
    if (stat_buf == NULL)
    {
        log_fatal_errno("Failed to allocate memory for stat buffer", errno);
        exit(EXIT_FAILURE);
    }

    /* Perform the stat */
    if (stat(current->shell, stat_buf) != 0)
    {
        log_error_errno_loc(ar, "Failed to run stat on file", current->shell, errno);
        free(stat_buf);
        return;
    }

    /* Test if the login shell is writable */
    if (stat_buf->st_mode & S_IWOTH)
        add_issue(HIGH, CTF, current->shell, ar, "Found a that's login shell is writable", "");

    free(stat_buf);
    return;
}

/**
 * Checks that the users home directory exists 
 * @param current This is the current /etc/passwd line that has been parsed
 * @param ar enumy's results
 */
static void check_home_exists(Parsed_Passwd_Line *current, All_Results *ar)
{
    if (access(current->home, F_OK) == -1)
        add_issue(HIGH, CTF, current->home, ar, "Found a home directory that does not exist, but is attached to an existing user", current->username);
}

/**
 * Checks to see if password hashes are stored in /etc/passwd
 * @param current This is the current /etc/passwd line that has been parsed
 * @param ar enumy's results
 */
static void check_password_hashes(Parsed_Passwd_Line *current, All_Results *ar)
{
    if (strcmp("x", current->password) != 0)
        add_issue(HIGH, CTF, PasswdLoc, ar, "Found password hashes in /etc/passwd", "");
}

/* ============================ PARSING FUNCTIONS  ============================== */

/**
 * This function will parse the contents of /etc/passwd and return a vector 
 * @param ar enumy's results
 * @returns a pointer to a vector containing the Parsed_Passwd_Line or NULL on error
 */
static vec_void_t *parse_etc_passwd(All_Results *ar)
{
    char current_line[MAXSIZE] = "";
    FILE *fp;

    /* Allocate memory for the vector */
    vec_void_t *passwd_vec = malloc(sizeof(vec_void_t));
    if (!passwd_vec)
    {
        log_fatal_errno("Failed to allocate memory for the passwd vector", errno);
        exit(EXIT_FAILURE);
    }

    /* Initilize the vector */
    vec_init(passwd_vec);

    /* Open /etc/passwd */
    fp = fopen(PasswdLoc, "r");
    if (!fp)
    {
        log_error_errno_loc(ar, "Failed to open passwd file", PasswdLoc, errno);
        vec_deinit(passwd_vec);
        free(passwd_vec);
        return NULL;
    }

    /* Loop through each line */
    while (fgets(current_line, sizeof current_line, fp))
    {
        /* Allocate memory for the parsed line struct */
        Parsed_Passwd_Line *current_parsed_line = (Parsed_Passwd_Line *)malloc(sizeof(Parsed_Passwd_Line));
        if (!current_parsed_line)
        {
            log_fatal_errno("Failed to allocate memory for the parsed passwd line struct", errno);
            exit(EXIT_FAILURE);
        }

        /* Actually parse the line */
        if (parse_etc_passwd_line(current_line, (Parsed_Passwd_Line *)current_parsed_line, ar))
            vec_push(passwd_vec, current_parsed_line);

        else
            free(current_parsed_line);
    }

    fclose(fp);
    return passwd_vec;
}

/**
 * This function will take a single line from /etc/password and tokenize the contents of the line
 * into the storage struct. 
 * @param current_line The current line to parse
 * @param storage The place to store the tokenized line
 * @param ar All the results (needed for the logger)
 */
static bool parse_etc_passwd_line(char *current_line, Parsed_Passwd_Line *storage, All_Results *ar)
{
    /* 0       :1       :2  :3  :4           :5       :6 */
    /* username:password:UID:GID:User_comment:home_dir:command */

    int token_n = 0;
    int char_count = 0;
    int line_len = strlen(current_line);
    char temp_buff[MAXSIZE] = {'\0'};

    for (int x = 0; x < line_len; x++)
    {
        /* Tokenize the line */
        if (current_line[x] == ':')
        {
            /* Username */
            if (token_n == 0)
                strncpy(storage->username, temp_buff, sizeof(storage->username));

            /* Password */
            else if (token_n == 1)
                strncpy(storage->password, temp_buff, sizeof(storage->password));

            /* UID */
            else if (token_n == 2)
            {
                if (!parse_int(temp_buff, &storage->uid))
                {
                    log_error_loc(ar, "Failed to parse UID in /etc/passwd, integer underflow/overflow", current_line);
                    return false;
                }
            }

            /* GID */
            else if (token_n == 3)
            {
                if (!parse_int(temp_buff, &storage->gid))
                {
                    log_error_loc(ar, "Failed to parse GID in /etc/passwd, integer underflow/overflow", current_line);
                    return false;
                }
            }
            /* Home */
            else if (token_n == 5)
                strncpy(storage->home, temp_buff, sizeof(storage->home));

            /* Reset ready for the next field */
            char_count = 0;
            token_n++;
            memset(temp_buff, '\0', sizeof(temp_buff));
            continue;
        }

        /* Copy the current character into the temp buffer */
        temp_buff[char_count] = current_line[x];
        char_count++;

        /* Shell */
        if ((token_n == 6) || (x == line_len - 1))
            strncpy(storage->shell, temp_buff, sizeof(storage->shell));
    }
    return true;
}

/**
 * This function will convert string represetation of an int and convert it
 * into an unsigned int
 * @param s The int represented as a string
 * @param i_ptr The place to save the int
 */
static bool parse_int(char *s, unsigned int *i_ptr)
{
    long int temp_int = strtol(s, NULL, 10);
    if (temp_int == LONG_MIN)
        return false;
    *i_ptr = (unsigned int)temp_int;
    return true;
}