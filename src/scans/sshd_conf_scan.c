/*
    This scan looks for ways the the SSH daemon could've been configured insecurly 
*/

#define _GNU_SOURCE

#include "results.h"
#include "debug.h"
#include "main.h"
#include "vector.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SSHD_CONF_LOC "/etc/ssh/sshd_config"

static int search_vector(Vector *v, char *key);
static void strip_trailing_comments(char *line);
static bool is_line_commented(char *current_line);

static void permit_empty_password_scan(All_Results *ar, Args *cmdline, Vector *v);
static void banner_enabled_scan(All_Results *ar, Args *cmdline, Vector *v);
static void host_based_auth_scan(All_Results *ar, Args *cmdline, Vector *v);
static void gss_api_auth_scan(All_Results *ar, Args *cmdline, Vector *v);
static void permit_root_login_scan(All_Results *ar, Args *cmdline, Vector *v);
static void x11_forwarding_scan(All_Results *ar, Args *cmdline, Vector *v);
static bool read_config_file(Vector *v, char *location);

/**
 * This scan is used to find misconfiguration inside of the SSHD configuration files. Example issues 
 * could be that login without a password is allowed
 * @param all_results this is a structure containing all the results that enumy has previously found
 * @param cmdline this is the list of runtime arguments passed at the command line 
 */
void sshd_conf_scan(All_Results *all_results, Args *cmdline)
{
    Vector lines;
    vector_init(&lines);

    if (!read_config_file(&lines, SSHD_CONF_LOC))
    {
        DEBUG_PRINT("%s", "Skipping sshd config test\n");
        return;
    }

    permit_empty_password_scan(all_results, cmdline, &lines);
    banner_enabled_scan(all_results, cmdline, &lines);
    host_based_auth_scan(all_results, cmdline, &lines);
    gss_api_auth_scan(all_results, cmdline, &lines);
    permit_root_login_scan(all_results, cmdline, &lines);
    x11_forwarding_scan(all_results, cmdline, &lines);
}

/**
 * This scan is used to check if the PermitEmptyPassword is enabled in the sshd config 
 * When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings.
 * The default is no.
 * @param ar this is a struct containing all of the previously found results 
 * @param cmdline this is a list of cmdline arguments passed at runtime
 */
static void permit_empty_password_scan(All_Results *ar, Args *cmdline, Vector *v)
{

    char *name = "SSHD Access via empty password is allowed";
    int index = search_vector(v, "PermitEmptyPassword");
    if (index == -1)
    {
        return;
    }

    if (strstr((char *)vector_get(v, index), " yes") != NULL)
    {
        int id = 265;
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(SSHD_CONF_LOC, new_result);
        set_issue_name(name, new_result);
        set_other_info((char *)vector_get(v, index), new_result);
        add_new_result_high(new_result, ar, cmdline);
    }
}

/**
 * This scan is used to check if the PermitEmptyPassword is enabled in the sshd config 
 * When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings.
 * The default is no.
 * @param ar this is a struct containing all of the previously found results 
 * @param cmdline this is a list of cmdline arguments passed at runtime
 */
static void banner_enabled_scan(All_Results *ar, Args *cmdline, Vector *v)
{
    char *name = "SSHD No SSH warning banner";
    int index = search_vector(v, "Banner");

    if (index == -1)
    {
        int id = 266;
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(SSHD_CONF_LOC, new_result);
        set_issue_name(name, new_result);
        set_other_info("", new_result);
        add_new_result_low(new_result, ar, cmdline);
        return;
    }
    if (strstr((char *)vector_get(v, index), " none") != NULL)
    {
        int id = 266;
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(SSHD_CONF_LOC, new_result);
        set_issue_name(name, new_result);
        set_other_info((char *)vector_get(v, index), new_result);
        add_new_result_high(new_result, ar, cmdline);
    }
}

/**
 * This checks ill see if host based authentication is allowed.
 * Rational SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.
 * HostbasedAuthentication default value is no 
 * @param ar this is a struct containing all of the previously found results 
 * @param cmdline this is a list of cmdline arguments passed at runtime
 */
static void host_based_auth_scan(All_Results *ar, Args *cmdline, Vector *v)
{

    char *name = "SSHD HostBasedAuthentication is enabled";
    int index = search_vector(v, "Banner");

    if (index == -1)
    {
        return;
    }
    if (strstr((char *)vector_get(v, index), " yes") != NULL)
    {
        int id = 267;
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(SSHD_CONF_LOC, new_result);
        set_issue_name(name, new_result);
        set_other_info((char *)vector_get(v, index), new_result);
        add_new_result_high(new_result, ar, cmdline);
        return;
    }
}

/**
 * This checks will scan and see if the GSSAPIAuthentication has been enabled 
 * it is disabled by default 
 * GSSAPI authentication is used to provide additional authentication mechanisms to applications.
 * Allowing GSSAPI authentication through SSH exposes the system's GSSAPI to remote hosts,
 * increasing the attack surface of the system.
 * @param ar this is a struct containing all of the previously found results 
 * @param cmdline this is a list of cmdline arguments passed at runtime
 */
static void gss_api_auth_scan(All_Results *ar, Args *cmdline, Vector *v)
{

    char *name = "SSHD GSSAPIAuthentication is enabled";
    int index = search_vector(v, "GSSAPIAuthentication");

    if (index == -1)
    {
        return;
    }
    if (strstr((char *)vector_get(v, index), " yes") != NULL)
    {
        int id = 268;
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(SSHD_CONF_LOC, new_result);
        set_issue_name(name, new_result);
        set_other_info((char *)vector_get(v, index), new_result);
        add_new_result_low(new_result, ar, cmdline);
        return;
    }
}

/**
 * This scan will check to see if root is allowed to login via ssh 
 * This should be disabled as it's always better to login in as a low priv
 * account and upgrade the privilage. 
 * The default value for this is prohibit-password this is not the most 
 * secure value and should be set to "no"
 * @param ar this is a struct containing all of the previously found results 
 * @param cmdline this is a list of cmdline arguments passed at runtime
 */
static void permit_root_login_scan(All_Results *ar, Args *cmdline, Vector *v)
{

    int id = 269;
    int index = search_vector(v, "PermitRootLogin");

    if (index == -1)
    {
        char *name = "SSHD PermitRootLogin is set to prohibit-password";
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(SSHD_CONF_LOC, new_result);
        set_issue_name(name, new_result);
        add_new_result_medium(new_result, ar, cmdline);
        return;
    }
    if (strstr((char *)vector_get(v, index), " no") != NULL)
    {
        char *name = "SSHD PermitRootLogin configurition could be more secure";
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(SSHD_CONF_LOC, new_result);
        set_issue_name(name, new_result);
        set_other_info((char *)vector_get(v, index), new_result);
        add_new_result_medium(new_result, ar, cmdline);
        return;
    }
}

/**
 * X11 forwarding allows GUI use over SSH. This should not be enabled unless
 * required. The default value is no
 * @param ar this is a struct containing all of the previously found results 
 * @param cmdline this is a list of cmdline arguments passed at runtime
 */
static void x11_forwarding_scan(All_Results *ar, Args *cmdline, Vector *v)
{

    int id = 270;
    int index = search_vector(v, "X11Forwarding");

    if (index == -1)
    {
        return;
    }
    if (strstr((char *)vector_get(v, index), " yes") != NULL)
    {
        char *name = "SSHD X11Forwarding is enabled";
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(SSHD_CONF_LOC, new_result);
        set_issue_name(name, new_result);
        set_other_info((char *)vector_get(v, index), new_result);
        add_new_result_medium(new_result, ar, cmdline);
        return;
    }
}

/**
 * This function will read a config file line by line and ignore 
 * @param v This is a vector that will be initiliazed an hold the results 
 * @param location this is the location of the file that's going to be read
 */
static bool read_config_file(Vector *v, char *location)
{
    FILE *fp;
    char buffer[MAXSIZE];
    char *buffer_cpy;

    if (access(location, F_OK) == -1)
    {
        DEBUG_PRINT("SSHD config file could not be found at location -> %s\n", location);
        return false;
    }

    fp = fopen(location, "r");

    if (fp == NULL)
    {
        DEBUG_PRINT("SSHD config file exists at location -> %s but is not readable\n", location);
        return false;
    }

    while (fgets(buffer, MAXSIZE - 1, fp))
    {
        if (is_line_commented(buffer) == true)
        {
            continue;
        }
        strip_trailing_comments(buffer);
        if (strcmp(buffer, "\n") != 0)
        {
            buffer_cpy = strdup(buffer);
            vector_add(v, buffer_cpy);
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
    char current_char;
    char space = ' ';
    char tab = '\t';
    char ret = '\r';
    char com = '#';

    for (int i = 0; i < len; i++)
    {
        current_char = current_line[i];
        if (
            current_char == space ||
            current_char == tab ||
            current_char == ret)
        {
            continue;
        }
        if (current_char == com)
        {
            return true;
        }
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
    char current_character;

    for (int i = 0; i < len; i++)
    {
        current_character = line[i];
        if (current_character == '#')
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
static int search_vector(Vector *v, char *key)
{
    int vector_size = vector_total(v);

    for (int i = vector_size - 1; i >= 0; i--)
    {
        if (strstr((char *)vector_get(v, i), key) != NULL)
        {
            return i;
        }
    }
    return -1;
}
