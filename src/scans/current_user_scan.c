/*
    This file is used to show some useful output to the screen
    if you've ever used LinEnum it should be a smaller version of that 

    The results from this are never saved and are only there as helpful
    information for the pentester to read while waiting for the scan to 
    complete
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
 * This is not really a scan but will display the output of some useful bash commands
 * heavily inspired by the popular LinEnum.sh script found at https://github.com/rebootuser/LinEnum
 * The idea of this is give the analyst some useful information to look at while waiting for the scan
 * to complete. Currently the output from this scan is NOT saved in the final results.
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

/**
 * This function is used to execute system commands such as cat, etc. 
 * The output from these commands are coppied into a buffer and then printed 
 * to the screen in a nice format 
 * @param cmd this is the shell comamnd to execute 
 * @param heading This is the label to give the output 
 * @param line this is either ONE_LINE or MULTI_LINE and effects the formating 
 */
static void execute_command_show_output(char *cmd, char *heading, bool line)
{
    FILE *fp = popen(cmd, "r");

    /* Format the heading */
    if (line == ONE_LINE)
        print_heading_oneliner(heading);
    else
        print_heading(heading);

    /* print the actual results */
    if (fp != NULL)
    {
        char buf[MAXSIZE];
        size_t byte_count = fread(buf, 1, MAXSIZE - 1, fp);
        buf[byte_count] = 0;

        printf("%s", buf);

        pclose(fp);
        return;
    }
}