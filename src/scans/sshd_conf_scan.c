/*
    This scan looks for ways the the SSH daemon could've been configured insecurly 
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "debug.h"
#include "error_logger.h"
#include "main.h"
#include "results.h"
#include "vector.h"

/* ============================ DEFINES ============================== */

#define SSHD_CONF_LOC "/etc/ssh/sshd_config"

/* ============================ PROTOTYPES ============================== */

void sshd_conf_scan(All_Results *all_results);

static int search_vector(vec_str_t *v, char *key);
static void strip_trailing_comments(char *line);
static bool is_line_commented(char *current_line);

static void permit_empty_password_scan(All_Results *ar, vec_str_t *v);
static void banner_enabled_scan(All_Results *ar, vec_str_t *v);
static void host_based_auth_scan(All_Results *ar, vec_str_t *v);
static void gss_api_auth_scan(All_Results *ar, vec_str_t *v);
static void permit_root_login_scan(All_Results *ar, vec_str_t *v);
static void x11_forwarding_scan(All_Results *ar, vec_str_t *v);
static bool read_config_file(All_Results *ar, vec_str_t *v, char *location);

/* ============================ FUNCTIONS ============================== */

/**
 * SSH is widely used and it very common for ssh to be configured insecurly
 * this scan will look for common misconfiguration such as being able to log 
 * into SSH directly as root user
 * @param all_results This is the structure that holds the link lists with the results 
 */
void sshd_conf_scan(All_Results *all_results)
{
    vec_str_t lines;
    vec_init(&lines);

    /* Try and read the SSH config file into a vector */
    if (!read_config_file(all_results, &lines, SSHD_CONF_LOC))
    {
        log_warn_loc(all_results, "Failed to find SSHD conf", SSHD_CONF_LOC);
        return;
    }

    /* Run the scans using the content of the vector */
    permit_empty_password_scan(all_results, &lines);
    banner_enabled_scan(all_results, &lines);
    host_based_auth_scan(all_results, &lines);
    gss_api_auth_scan(all_results, &lines);
    permit_root_login_scan(all_results, &lines);
    x11_forwarding_scan(all_results, &lines);

    /* Destroy the vectos */
    for (int i = 0; i < lines.length; i++)
        free(lines.data[i]);

    vec_deinit(&lines);
}

/* ============================ STATIC FUNCTIONS ============================== */

/**
 * This scan is used to check if the PermitEmptyPassword is enabled in the sshd config 
 * When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings.
 * The default is no.
 * @param ar this is a struct containing all of the previously found results 
 * @param v this is the vector containing all of the config information 
 */
static void permit_empty_password_scan(All_Results *ar, vec_str_t *v)
{
    int index = search_vector(v, "PermitEmptyPassword");
    if (index == -1)
        return;

    if (strstr(v->data[index], " yes") != NULL)
        add_issue(HIGH, AUDIT, SSHD_CONF_LOC, ar, "SSHD Access via empty password is allowed", v->data[index]);
}

/**
 * This scan is used to check if the PermitEmptyPassword is enabled in the sshd config 
 * When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings.
 * The default is no.
 * @param ar this is a struct containing all of the previously found results 
 * @param v this is the vector containing all of the config information 
 */
static void banner_enabled_scan(All_Results *ar, vec_str_t *v)
{
    int index = search_vector(v, "Banner");

    if (index == -1)
    {
        add_issue(LOW, AUDIT, SSHD_CONF_LOC, ar, "SSHD SSH warning banner not configured", "");
        return;
    }
    if (strstr(v->data[index], " none") != NULL)
        add_issue(HIGH, AUDIT, SSHD_CONF_LOC, ar, "SSHD NO SSH warning banner", v->data[index]);
}

/**
 * This checks ill see if host based authentication is allowed.
 * Rational SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.
 * HostbasedAuthentication default value is no 
 * @param ar this is a struct containing all of the previously found results 
 * @param v this is the vector containing all of the config information 
 */
static void host_based_auth_scan(All_Results *ar, vec_str_t *v)
{
    int index = search_vector(v, "Banner");

    if (index == -1)
        return;

    if (strstr(v->data[index], " yes") != NULL)
        add_issue(HIGH, AUDIT, SSHD_CONF_LOC, ar, "SSHD HostBasedAuthentication is enabled", v->data[index]);
}

/**
 * This checks will scan and see if the GSSAPIAuthentication has been enabled 
 * it is disabled by default 
 * GSSAPI authentication is used to provide additional authentication mechanisms to applications.
 * Allowing GSSAPI authentication through SSH exposes the system's GSSAPI to remote hosts,
 * increasing the attack surface of the system.
 * @param ar this is a struct containing all of the previously found results 
 * @param v this is the vector containing all of the config information 
 */
static void gss_api_auth_scan(All_Results *ar, vec_str_t *v)
{
    int index = search_vector(v, "GSSAPIAuthentication");

    if (index == -1)
        return;

    if (strstr(v->data[index], " yes") != NULL)
        add_issue(LOW, AUDIT, SSHD_CONF_LOC, ar, "SSHD GSSAPIAuthentication is enabled", v->data[index]);
}

/**
 * This scan will check to see if root is allowed to login via ssh 
 * This should be disabled as it's always better to login in as a low priv
 * account and upgrade the privilage. 
 * The default value for this is prohibit-password this is not the most 
 * secure value and should be set to "no"
 * @param ar this is a struct containing all of the previously found results 
 * @param v this is the vector containing all of the config information 
 */
static void permit_root_login_scan(All_Results *ar, vec_str_t *v)
{
    int index = search_vector(v, "PermitRootLogin");

    if (index == -1)
    {
        add_issue(MEDIUM, AUDIT, SSHD_CONF_LOC, ar, "SSHD PermitRootLogin is set to prohibit-password", "");
        return;
    }

    if (strstr(v->data[index], " no") != NULL)
        add_issue(MEDIUM, AUDIT, SSHD_CONF_LOC, ar, "SSHD PermitRootLogin configuration coudld be more secure", v->data[index]);
}

/**
 * X11 forwarding allows GUI use over SSH. This should not be enabled unless
 * required. The default value is no
 * @param ar this is a struct containing all of the previously found results 
 * @param v this is the vector containing all of the config information 
 */
static void x11_forwarding_scan(All_Results *ar, vec_str_t *v)
{
    int index = search_vector(v, "X11Forwarding");

    if (index == -1)
        return;

    if (strstr(v->data[index], " yes") != NULL)
        add_issue(MEDIUM, AUDIT, SSHD_CONF_LOC, ar, "SSHD X11Forwarding is enabled", v->data[index]);
}

/**
 * This function will read a config file line by line and ignore 
 * @param v This is a vector that will be initiliazed an hold the results 
 * @param location this is the location of the file that's going to be read
 */
static bool read_config_file(All_Results *ar, vec_str_t *v, char *location)
{
    FILE *fp;
    char buffer[MAXSIZE];
    char *buffer_cpy;

    /* Open the file */
    fp = fopen(location, "r");
    if (fp == NULL)
    {
        log_warn_errno_loc(ar, location, "Failed to read the SSHD configuration file", errno);
        return false;
    }

    /* Read the file line by line adding the lines */
    while (fgets(buffer, MAXSIZE - 1, fp))
    {
        /* Skip commented lines */
        if (is_line_commented(buffer) == true)
            continue;

        /* Truncate uncessicery comments */
        strip_trailing_comments(buffer);

        if (strcmp(buffer, "\n") != 0)
        {
            buffer_cpy = strdup(buffer);
            if (buffer_cpy == NULL)
            {
                log_fatal_errno("Failed to allocate memory while reading SSHD conf", errno);
                exit(EXIT_FAILURE);
            }
            vec_push(v, buffer_cpy);
        }
    }
    fclose(fp);
    return true;
}

/**
 * Ignoring whitespace this function will itterate through the line's 
 * characters and see if the first non white space character is a #
 * @param current_line the line to be searched 
 * @return true if the line is commmented out
 */
static bool is_line_commented(char *current_line)
{
    int len = strlen(current_line);
    char space = ' ';
    char tab = '\t';
    char ret = '\r';
    char com = '#';

    /* Loop through the current line */
    for (int i = 0; i < len; i++)
    {
        char current_char = current_line[i];

        /* Ignore whitespace */
        if (
            current_char == space ||
            current_char == tab ||
            current_char == ret)
        {
            continue;
        }
        /* Line is commented */
        if (current_char == com)
            return true;

        return false;
    }
    return true;
}

/**
 * This function will truncate any trailing comments found in the str line
 * @param line the line to be truncated
 */
static void strip_trailing_comments(char *line)
{
    int len = strlen(line);

    /* Loop through current line */
    for (int i = 0; i < len; i++)
    {
        if (line[i] == '#')
        {
            line[i] = '\0';
            return;
        }
    }
}

/**
 * This will search through all of the lines in the config file that are 
 * stored in the vector v and return the last matching value. 
 * @param v The vector containing the config files lines
 * @param key the value that we're searching for 
 * @return -1 if not found or the index in the vector if found
 */
static int search_vector(vec_str_t *v, char *key)
{
    /* Loop through the vector */
    for (int i = v->length - 1; i >= 0; i--)
    {
        if (strstr(v->data[i], key) != NULL)
            return i;
    }
    return -1;
}
