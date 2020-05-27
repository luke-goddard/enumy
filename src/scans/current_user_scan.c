/*
Current user details
Last logged on users
Shows users logged onto the host
List all users including uid/gid information
List root accounts
Extracts password policies and hash storage method information
Checks umask value
Checks if password hashes are stored in /etc/passwd
Extract full details for ‘default’ uid’s such as 0, 1000, 1001 etc
Attempt to read restricted files i.e. /etc/shadow
List current users history files (i.e .bash_history, .nano_history etc.)
Basic SSH checks
*/

#include "debug.h"
#include "results.h"
#include "scan.h"
#include "utils.h"
#include "vector.h"

#include <stdio.h>
#include <stdbool.h>

/* ============================ DEFINES ============================== */

#define ONE_LINE false
#define MULT_LINE true

/* ============================ PROTOTYPES ============================== */

static void execute_command_show_output(char *cmd, char *heading, bool line);

/* ============================ FUNCTIONS ============================== */

/**
 * This function kicks off all of the current user scans 
 */
void current_user_scan()
{
    execute_command_show_output("id", "Current User Info", ONE_LINE);
    execute_command_show_output("cat /proc/version", "Version", ONE_LINE);
    execute_command_show_output("cat /etc/hostname", "hostname", ONE_LINE);
    execute_command_show_output("umask -S", "Umask", ONE_LINE);
    execute_command_show_output("lastlog 2>/dev/null | grep -v 'Never' 2>/dev/null", "Last Login", MULT_LINE);
    execute_command_show_output("cat /etc/passwd | grep -v 'nologin'", "User Accounts", MULT_LINE);
    execute_command_show_output("w", "Who Else Is Logged On", MULT_LINE);
    execute_command_show_output("for i in $(cut -d ':' -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null",
                                "Groups", MULT_LINE);
    puts("");
}

/* ============================ STATIC FUNCTIONS ============================== */

static void execute_command_show_output(char *cmd, char *heading, bool line)
{
    char buf[MAXSIZE];
    FILE *fp = popen(cmd, "r");

    if (line == ONE_LINE)
        print_heading_oneliner(heading);
    else
        print_heading(heading);

    if (fp != NULL)
    {
        size_t byte_count = fread(buf, 1, MAXSIZE - 1, fp);
        buf[byte_count] = 0;
        printf("%s", buf);
        pclose(fp);
        return;
    }
}