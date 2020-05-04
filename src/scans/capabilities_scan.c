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

static bool check_audit_control(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_audit_read(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_audit_write(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);

static bool check_block_suspend(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_chown(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_dac_bypass(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);

static bool check_dac_read_search(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_fowner(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_clear_set_id(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);

static bool check_ipc_lock(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_ipc_owner(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_kill(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);

static bool check_lease(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_immutable(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_mac_admin(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);

static bool check_mac_override(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_mknod(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_net_admin(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);

static bool check_net_bind_service(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_net_broadcast(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_net_raw(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);

static bool check_sys_nice(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_set_gid(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_set_cap(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);

static bool check_set_pcap(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_set_uid(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_sys_admin(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);

static bool check_reboot(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_sys_chroot(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_sys_module(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);

static bool check_process_accounting(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_ptrace(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_sys_resource(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);

static bool check_sys_time(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_sys_tty(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_syslog(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);

static int check_cap(cap_t caps_for_file, cap_value_t search);
static void set_other_info_to_cap_flag(cap_flag_t flag, Result *new_result);

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
    {
        return findings;
    }

    int fd = open(fi->location, O_RDONLY);
    if (fd == -1)
    {
        return findings;
    }

    cap = cap_get_fd(fd);
    if (cap == NULL)
    {
        close(fd);
        return findings;
    }

    findings += (check_audit_control(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_audit_read(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_audit_write(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_block_suspend(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_chown(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_dac_bypass(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_dac_read_search(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_fowner(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_clear_set_id(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_ipc_lock(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_ipc_owner(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_kill(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_lease(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_immutable(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_mac_admin(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_mac_override(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_mknod(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_net_admin(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_net_bind_service(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_net_broadcast(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_net_raw(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_sys_nice(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_set_gid(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_set_cap(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_set_pcap(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_set_uid(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_sys_admin(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_reboot(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_sys_chroot(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_sys_module(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_process_accounting(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_ptrace(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_sys_resource(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_sys_time(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_sys_tty(cap, fi, ar, cmdline) == true) ? 1 : 0;
    findings += (check_syslog(cap, fi, ar, cmdline) == true) ? 1 : 0;

    cap_free(cap);
    close(fd);
    return findings;
}

/**
 * CAP_AUDIT_CONTROL (since Linux 2.6.11)
 * Enable and disable kernel auditing change auditing filter rules; retrieve auditing status and filtering rules.a
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_audit_control(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 7;
    char *name = "CAP_AUDIT_CONTROL capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_AUDIT_CONTROL);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_medium(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 * CAP_AUDIT_READ(since Linux 3.16)
 * Allow reading the audit log via a multicast netlink socket.a
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_audit_read(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 8;
    char *name = "CAP_AUDIT_READ capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_AUDIT_READ);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_medium(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_AUDIT_WRITE(since Linux 2.6.11)
 *  Write records to kernel auditing log.a
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_audit_write(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 9;
    char *name = "CAP_AUDIT_WRITE capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_AUDIT_WRITE);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_medium(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 * CAP_BLOCK_SUSPEND(since Linux 3.5)
 * Employ features that can block system suspend(epoll(7)a
 * EPOLLWAKEUP, /proc/sys/wake_lock).
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_block_suspend(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 10;
    char *name = "CAP_BLOCK_SUSPEND capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_BLOCK_SUSPEND);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_medium(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_CHOWN
 *  Make arbitrary changes to file UIDs and GIDa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_chown(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 11;
    char *name = "CAP_CHOWN capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_CHOWN);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_DAC_OVERRIDE
 *  Bypass file read, write, and execute permission checks.a
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_dac_bypass(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 12;
    char *name = "CAP_DAC_OVERRIDE capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_DAC_OVERRIDE);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_DAC_READ_SEARCH
 *  *Bypass file read permission checks and directory read and execute permission checks;
 * invoke open_by_handle_at(2);
 * use the linkat(2) AT_EMPTY_PATH flag to create a link to a file refred at fd
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_dac_read_search(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 13;
    char *name = "CAP_DAC_READ_SEARCH capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_DAC_READ_SEARCH);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_FOWNER
 *  Bypass permissions checks on operations that requrire UID inodes and ACLS Ignore sticky bitsa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_fowner(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 14;
    char *name = "CAP_FOWNER capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_FOWNER);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_FSETID
 *  Do not clear SUID/GUID bits on modified filesa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_clear_set_id(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 15;
    char *name = "CAP_FSETID capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_FSETID);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_IPC_LOCK
 *  Lock memorya
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_ipc_lock(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 16;
    char *name = "CAP_IPC_LOCK capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_IPC_LOCK);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_medium(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_IPC_OWNER
 *  Bypass permission checks for operations on System V IPC objectsa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_ipc_owner(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 17;
    char *name = "CAP_IPC_OWNER capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_IPC_OWNER);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_medium(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_KILL
 *  Bypass permisssion checks for ssending signalsa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_kill(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 18;
    char *name = "CAP_KILL capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_KILL);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_medium(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_LEASE
 *  Establish leases on arbitrary filesa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_lease(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 19;
    char *name = "CAP_LEASE capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_LEASE);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_LINUX_IMMUTABLE
 *  Set the immutable flag on a filea
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_immutable(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 20;
    char *name = "CAP_LINUX_IMMUTABLE capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_LINUX_IMMUTABLE);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_low(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_MAC_ADMIN
 *  Change the smack linux security module configurationa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_mac_admin(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 21;
    char *name = "CAP_MAC_ADMIN capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_MAC_ADMIN);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_MAC_OVERRIDE
 *  Override mandatory access control for Smack LSMa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_mac_override(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 22;
    char *name = "CAP_MAC_OVERRIDE capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_MAC_OVERRIDE);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_MKNOD
 *  Create special files using mknoda
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_mknod(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 23;
    char *name = "CAP_MKNOD capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_MKNOD);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_low(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_NET_ADMIN
 *  Perform shit tons of powerful networking operationsa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_net_admin(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 24;
    char *name = "CAP_NET_ADMIN capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_NET_ADMIN);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_NET_BIND_SERVICE
 *  Bind to ports less than 1024a
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_net_bind_service(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 25;
    char *name = "CAP_NET_BIND_SERVICE capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_NET_BIND_SERVICE);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_NET_BROADCAST
 *  Make a socket broadcasts and listen to multicasta
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_net_broadcast(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 26;
    char *name = "CAP_NET_BROADCAST capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_NET_BROADCAST);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_medium(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_NET_RAW
 *  Use raw and packet sockets, bind to any address for transparent proxya
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_net_raw(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 27;
    char *name = "CAP_NET_RAW capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_NET_RAW);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_SETGID
 *  Manipulate GID lista
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_set_gid(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 28;
    char *name = "CAP_SETGID capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_SETGID);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_SETFCAP
 *  set capablities on filesa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_set_cap(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 29;
    char *name = "CAP_SETGID capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_SETFCAP);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_SETPCAP
 *  Same as CAP_SETFCAP but for processesa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_set_pcap(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 30;
    char *name = "CAP_SETPCAP capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_SETPCAP);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_SETUID
 *  Manipulatee process UID'sa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_set_uid(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 31;
    char *name = "CAP_SETTUID capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_SETUID);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_SYS_ADMIN
 *  perform load of low level operationsa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_sys_admin(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 32;
    char *name = "CAP_SYS_ADMIN capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_SYS_ADMIN);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_SYS_BOOT
 *  Perform rebootsa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_reboot(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 33;
    char *name = "CAP_SYS_BOOT capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_SYS_BOOT);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_low(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_SYS_CHROOT
 *  Allows you to change roota
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_sys_chroot(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 34;
    char *name = "CAP_SYS_CHROOT capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_SYS_CHROOT);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_SYS_MODULE
 *  Allows you to load and unload kernel modulesa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_sys_module(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 35;
    char *name = "CAP_SYS_MODULE capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_SYS_MODULE);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_SYS_NICE
 *  Change kernels schelduling priorirtiesa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_sys_nice(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 36;
    char *name = "CAP_SYS_NICE capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_SYS_NICE);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_low(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_SYS_PACCT
 *  Change kernels schelduling priorirtiesa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_process_accounting(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 37;
    char *name = "CAP_SYS_PACCT capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_SYS_PACCT);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_medium(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_SYS_PTRACE
 *  Allows the use of ptrace syscalla
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_ptrace(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 38;
    char *name = "CAP_SYS_PTRACE capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_SYS_PTRACE);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_SYS_RESOURCE
 *  TODO: figure out what this capability does doesa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_sys_resource(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 39;
    char *name = "CAP_SYS_RESOURCE capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_SYS_RESOURCE);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_low(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_SYS_TIME
 *  Change system clock and the hardware clocka
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_sys_time(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 40;
    char *name = "CAP_SYS_TIME capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_SYS_TIME);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_low(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_SYS_TTY_CONFIG
 *  Perform privilaged operations on TTY terminalsa
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_sys_tty(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 41;
    char *name = "CAP_SYS_TIME capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_SYS_TTY_CONFIG);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_low(new_result, ar, cmdline);
        return true;
    }
    return true;
}

/**
 *  CAP_SYSLOG
 *  Perform privilaged syslog opertaions and view kernel addresses exposed via /proca
 * @param caps_for_file the capability that we're searching for
 * @param fi the current files information 
 * @param ar A struct containing all issues that enumy hass found 
 * @param cmdline A struct containing all the runtime arguments 
 */
static bool check_syslog(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 41;
    char *name = "CAP_SYSLOG capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_SYSLOG);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
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
    {
        return CAP_PERMITTED;
    }
    flag = CAP_INHERITABLE;
    cap_get_flag(caps_for_file, search, flag, &value_p);
    if (value_p == CAP_SET)
    {
        return CAP_INHERITABLE;
    }
    flag = CAP_EFFECTIVE;
    cap_get_flag(caps_for_file, search, flag, &value_p);
    if (value_p == CAP_SET)
    {
        return CAP_EFFECTIVE;
    }
    return 0;
}

/**
 * Just sets the issues other info value to the string representation of the flag
 * @param flag CAP_PERMITED | CAP_INHERITABLE | CAP_EFFECTIVE
 * @param new_result the location of the new result
 */
static void set_other_info_to_cap_flag(cap_flag_t flag, Result *new_result)
{
    if (flag == CAP_PERMITTED)
    {
        set_other_info("Capabilities flag set to -> CAP_PERMITTED", new_result);
    }
    else if (flag == CAP_INHERITABLE)
    {
        set_other_info("Capabilities flag set to -> CAP_INHERITIABLE", new_result);
    }
    else if (flag == CAP_EFFECTIVE)
    {
        set_other_info("Capabilities flag set to -> CAP_EFFECTIVE", new_result);
    }
}