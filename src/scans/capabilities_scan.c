/*
    Capabilities allow the kernel to give a file elevated permissions while performing a task that
    would require a high privilaged UID. This means that we could abuse these files if found and 
    the file is found to be exploitable in some way

    Man page:
    For the purpose of performing permission checks, traditional UNIX implementations distinguish two 
    categories of processes: privileged processes (whose effective user ID is 0, referred to as 
    superuser or root), and unprivileged processes (whose effective UID is nonzero).
    Privileged processes bypass all kernel permission checks, while unprivileged processes are subject to
    full permission checking based on the process's credentials
    (usually: effective UID, effective GID, and supplementary group list).

    Starting with kernel 2.2, Linux divides the privileges traditionally associated with superuser into
    distinct units, known as capabilities, which can be independently enabled and disabled. 
    Capabilities are a per-thread attribute.
*/

#include "results.h"
#include "file_system.h"
#include "main.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/capability.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

/* ============================ PROTOTYPES ============================== */

static int check_cap(cap_t caps_for_file, cap_value_t search);
static void add_issue_wrapper(int issue_type, int id, File_Info *fi, All_Results *ar, Args *cmdline, char *issue_name);
static void scan_cap(int issue_serverity, cap_t current_caps, File_Info *fi, All_Results *ar, Args *cmdline, char *issue_name, cap_value_t cap_to_find);

/**
 * given a file with it's information in fi, this function will test to see if
 * that file has any special linux capabilities that could be abused 
 * @param fi The current files information 
 * @param ar A structure containing all of the results that enumy has found 
 * @param cmdline the runtime arguments 
 * @return The number of capabilites that the file has 
 */
int capabilities_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;
    cap_t cap;

    if (!has_executable(fi))
        return findings;

    int fd = open(fi->location, O_RDONLY);
    if (fd == -1)
        return findings;

    cap = cap_get_fd(fd);
    if (cap == NULL)
    {
        close(fd);
        return findings;
    }

    // HIGH issue serverity
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_NET_BIND_SERVICE capablities enabled on file", CAP_NET_BIND_SERVICE);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_DAC_READ_SEARCH capablities enabled on file", CAP_DAC_READ_SEARCH);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_MAC_OVERRIDE capablities enabled on file", CAP_MAC_OVERRIDE);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_DAC_OVERRIDE capablities enabled on file", CAP_DAC_OVERRIDE);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_SYS_MODULE capablities enabled on file", CAP_SYS_MODULE);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_SYS_PTRACE capablities enabled on file", CAP_SYS_PTRACE);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_SYS_CHROOT capablities enabled on file", CAP_SYS_CHROOT);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_SYS_ADMIN capablities enabled on file", CAP_SYS_ADMIN);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_MAC_ADMIN capablities enabled on file", CAP_MAC_ADMIN);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_NET_ADMIN capablities enabled on file", CAP_NET_ADMIN);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_SETPCAP capablities enabled on file", CAP_SETPCAP);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_NET_RAW capablities enabled on file", CAP_NET_RAW);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_SETFCAP capablities enabled on file", CAP_SETFCAP);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_FSETID capablities enabled on file", CAP_FSETID);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_FOWNER capablities enabled on file", CAP_FOWNER);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_SETGID capablities enabled on file", CAP_SETGID);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_SETUID capablities enabled on file", CAP_SETUID);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_SYSLOG capablities enabled on file", CAP_SYSLOG);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_CHOWN capablities enabled on file", CAP_CHOWN);
    scan_cap(HIGH, cap, fi, ar, cmdline, "CAP_LEASE capablities enabled on file", CAP_LEASE);

    // MEDIUM issue serverity
    scan_cap(MEDIUM, cap, fi, ar, cmdline, "CAP_AUDIT_CONTROL capablities enabled on file", CAP_AUDIT_CONTROL);
    scan_cap(MEDIUM, cap, fi, ar, cmdline, "CAP_BLOCK_SUSPEND capablities enabled on file", CAP_BLOCK_SUSPEND);
    scan_cap(MEDIUM, cap, fi, ar, cmdline, "CAP_NET_BROADCAST capablities enabled on file", CAP_NET_BROADCAST);
    scan_cap(MEDIUM, cap, fi, ar, cmdline, "CAP_AUDIT_WRITE capablities enabled on file", CAP_AUDIT_WRITE);
    scan_cap(MEDIUM, cap, fi, ar, cmdline, "CAP_AUDIT_READ capablities enabled on file", CAP_AUDIT_READ);
    scan_cap(MEDIUM, cap, fi, ar, cmdline, "CAP_IPC_OWNER capablities enabled on file", CAP_IPC_OWNER);
    scan_cap(MEDIUM, cap, fi, ar, cmdline, "CAP_SYS_PACCT capablities enabled on file", CAP_SYS_PACCT);
    scan_cap(MEDIUM, cap, fi, ar, cmdline, "CAP_IPC_LOCK capablities enabled on file", CAP_IPC_LOCK);
    scan_cap(MEDIUM, cap, fi, ar, cmdline, "CAP_KILL capablities enabled on file", CAP_KILL);

    // LOW issue serverity
    scan_cap(LOW, cap, fi, ar, cmdline, "CAP_LINUX_IMMUTABLE capablities enabled on file", CAP_LINUX_IMMUTABLE);
    scan_cap(LOW, cap, fi, ar, cmdline, "CAP_SYS_RESOURCE capablities enabled on file", CAP_SYS_RESOURCE);
    scan_cap(LOW, cap, fi, ar, cmdline, "CAP_SYS_BOOT capablities enabled on file", CAP_SYS_BOOT);
    scan_cap(LOW, cap, fi, ar, cmdline, "CAP_SYS_NICE capablities enabled on file", CAP_SYS_NICE);
    scan_cap(LOW, cap, fi, ar, cmdline, "CAP_SYS_TIME capablities enabled on file", CAP_SYS_TIME);
    scan_cap(LOW, cap, fi, ar, cmdline, "CAP_MKNOD capablities enabled on file", CAP_MKNOD);

    cap_free(cap);
    close(fd);
    return findings;
}

/* ============================ STATIC FUNCTIONS ============================== */

/**
 * Wrapper function to check if the current file has a certain Linux capablity attached to it
 * @param issue_serverity If found how important is this linux capablity HIGH, MEDIUM, LOW
 * @param current_caps struct containing the current files linux capabilities
 * @param fi Struct containing the current files informationn
 * @param cmdline runtime arguments
 * @param issue_name If found what description should we give the issue
 * @param cap_to_find this is the cap_value that we're searching for
 */
static void scan_cap(int issue_serverity, cap_t current_caps, File_Info *fi, All_Results *ar, Args *cmdline, char *issue_name, cap_value_t cap_to_find)
{
    int cap_value = check_cap(current_caps, cap_to_find);

    if (cap_value)
        add_issue_wrapper(issue_serverity, 0, fi, ar, cmdline, issue_name);
}

/**
 * Wrapper function to short code to add new issue
 * @param issue_type If found how important is this linux capablity HIGH, MEDIUM, LOW
 * @param id The issue ID to be raised as 
 * @param fi Struct containing the current files informationn
 * @param cmdline runtime arguments
 * @param issue_name If found what description should we give the issue
 * @param cap_value This is the value of the capablity found
 */
static void add_issue_wrapper(int issue_type, int id, File_Info *fi, All_Results *ar, Args *cmdline, char *issue_name)
{
    add_issue(issue_type, id, fi->location, ar, cmdline, issue_name, "");
}

/**
 * Searches 'caps_for_file' for 'search' 
 * Effective ->     The effective set contains the capabilities that are currently active
 * Inheritable ->   The permitted set contains the capabilities that the process has the right to use.
 * Permited ->      The inheritable set contains the capabilities that can be inherited by children to the process
 * @param caps_for_file the files capabilities
 * @param search the capability that we're testing 
 * @return CAP_PERMITTED
 * @return CAP_INHERITABLE
 * @return CAP_EFFECTIVE
 */
static int check_cap(cap_t caps_for_file, cap_value_t search)
{
    cap_flag_t flag;                      // values for this type are CAP_EFFECTIVE, CAP_INHERITABLE or CAP_PERMITTED
    cap_flag_value_t value_p = CAP_CLEAR; // valid values for this type are CAP_CLEAR (0) or CAP_SET (1)

    flag = CAP_PERMITTED;
    cap_get_flag(caps_for_file, search, flag, &value_p);

    if (value_p == CAP_SET)
        return CAP_PERMITTED;

    flag = CAP_INHERITABLE;
    cap_get_flag(caps_for_file, search, flag, &value_p);

    if (value_p == CAP_SET)
        return CAP_INHERITABLE;

    flag = CAP_EFFECTIVE;
    cap_get_flag(caps_for_file, search, flag, &value_p);

    if (value_p == CAP_SET)
        return CAP_EFFECTIVE;

    return 0;
}