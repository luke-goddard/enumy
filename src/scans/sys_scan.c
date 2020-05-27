/*
    The point of this scan is to find out where /proc/sys can be hardened.
    Examples of this to disable the IPv4 forwarding setting 
*/

#include "main.h"
#include "results.h"
#include "scan.h"
#include "debug.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* ============================ DEFINES ============================== */

#define BAD_READ 0xDEADBEEF

/* ============================ PROTOTYPES ============================== */

void sys_scan(All_Results *ar, Args *args);

static bool check_location_exists(char *location);
static int read_proc_int(char *location);

static void check_kptr_restrict(All_Results *ar, Args *cmdline);
static void check_namespaces(All_Results *ar, Args *cmdline);
static void check_ptrace_scope(All_Results *ar, Args *cmdline);
static void check_kexec_load(All_Results *ar, Args *cmdline);
static void check_bpf_disabled(All_Results *ar, Args *cmdline);
static void check_bpf_jit_harden(All_Results *ar, Args *cmdline);
static void check_event_parranoid(All_Results *ar, Args *cmdline);
static void check_core_pattern(All_Results *ar, Args *cmdline);
static void check_dmesg_restrict(All_Results *ar, Args *cmdline);
static void check_protected_hardlinks(All_Results *ar, Args *cmdline);
static void check_protected_symlinks(All_Results *ar, Args *cmdline);
static void check_ipv4_tcp_syncookies(All_Results *ar, Args *cmdline);
static void check_ipv4_ip_forward(All_Results *ar, Args *cmdline);
static void check_ipv4_icmp_ignore_bogus_error_response(All_Results *ar, Args *cmdline);
static void check_ipv4_accept_source_route(All_Results *ar, Args *cmdline);
static void check_randomized_va_space(All_Results *ar, Args *cmdline);
static void check_ipv4_echo_ignore_broadcasts(All_Results *ar, Args *cmdline);
static void add_medium_issue(All_Results *ar, Args *cmdline, int id, char *loc, char *issue_name);

/* ============================ FUNCTIONS ============================== */

/**
 * This function kicks of all of the /proc/sys/ scans to see if their 
 * are any easy ways of hardening the kernel
 * @param ar This is the structure containing all the issues enumy has found
 * @param cmdline This is the runtime arguments for enumy 
 */
void sys_scan(All_Results *ar, Args *cmdline)
{
    check_kptr_restrict(ar, cmdline);
    check_namespaces(ar, cmdline);
    check_ptrace_scope(ar, cmdline);
    check_kexec_load(ar, cmdline);
    check_bpf_disabled(ar, cmdline);
    check_bpf_jit_harden(ar, cmdline);
    check_event_parranoid(ar, cmdline);
    check_core_pattern(ar, cmdline);
    check_dmesg_restrict(ar, cmdline);
    check_protected_hardlinks(ar, cmdline);
    check_protected_symlinks(ar, cmdline);
    check_ipv4_tcp_syncookies(ar, cmdline);
    check_ipv4_ip_forward(ar, cmdline);
    check_ipv4_icmp_ignore_bogus_error_response(ar, cmdline);
    check_ipv4_accept_source_route(ar, cmdline);
    check_ipv4_echo_ignore_broadcasts(ar, cmdline);
    check_randomized_va_space(ar, cmdline);
}

/* ============================ STATIC FUNCTIONS ============================== */

/**
 * /proc/sys/kernel/kptr_restrict
 * 0: When kptr_restrict is set to 0 (the default) the address is hashed before printing. (This is the equivalent to %p.)
 * 1: kernel pointers printed using the %pK format specifier will be replaced with 0's unless the user has CAP_SYSLOG 
 *    and effective user and group ids are equal to the real ids
 * @param ar This is the structure containing all the issues enumy has found
 * @param cmdline This is the runtime arguments for enumy 
 */
static void check_kptr_restrict(All_Results *ar, Args *cmdline)
{
    char *loc = "/proc/sys/kernel/kptr_restrict";
    char *issue_name = "sysctl kptr_restrict disabled";
    int id = 237;

    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, cmdline, id, loc, issue_name);
}

/**
 * /proc/sys/user/max_user_namespaces
 * The maximum number of user namespaces that any user in the current user name space may create 
 * @param ar This is the structure containing all the issues enumy has found
 * @param cmdline This is the runtime arguments for enumy 
 */
static void check_namespaces(All_Results *ar, Args *cmdline)
{
    char *loc = "/proc/sys/user/max_user_namespaces";
    char *issue_name = "sysctl namespaces enabled";
    int id = 238;

    if (check_location_exists(loc) && read_proc_int(loc) != 0)
        add_medium_issue(ar, cmdline, id, loc, issue_name);
}

/**
 * /proc/sys/kernel/yama/ptrace_scope
 * 0: all processes can be debugged, as long as they have same uid. This is the classical way of how ptracing worked.
 * 1: only a parent process can be debugged.
 * 2: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
 * 3: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.
 * @param ar This is the structure containing all the issues enumy has found
 * @param cmdline This is the runtime arguments for enumy 
 */
static void check_ptrace_scope(All_Results *ar, Args *cmdline)
{
    char *loc = "/proc/sys/kernel/yama/ptrace_scope";
    char *issue_name = "sysctl ptrace enabled";
    int id = 239;

    if (check_location_exists(loc) && read_proc_int(loc) != 3)
        add_medium_issue(ar, cmdline, id, loc, issue_name);
}

/**
 * /proc/sys/kernel/kexec_load_disabled
 * 0: (Default) kexec_load syscall enabled
 * 1: kexec_load syscall disabled (cannot be re-enabled)
 * @param ar This is the structure containing all the issues enumy has found
 * @param cmdline This is the runtime arguments for enumy 
 */
static void check_kexec_load(All_Results *ar, Args *cmdline)
{
    char *loc = "/proc/sys/kernel/kexec_load_disabled";
    char *issue_name = "sysctl kexec_load_disabled";
    int id = 240;

    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, cmdline, id, loc, issue_name);
}

/**
 * /proc/sys/kernel/unprivileged_bpf_disabled
 * 0: bpf() syscall for unprivileged users is enabled
 * 1: bpf() syscall restricted to privileged users
 * @param ar This is the structure containing all the issues enumy has found
 * @param cmdline This is the runtime arguments for enumy 
 */
static void check_bpf_disabled(All_Results *ar, Args *cmdline)
{
    char *loc = "/proc/sys/kernel/unprivileged_bpf_disabled";
    char *issue_name = "sysctl unprivileged_bpf_disabled";
    int id = 241;

    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, cmdline, id, loc, issue_name);
}

/**
 * /proc/sys/net/core/bpf_jit_harden
 * This enables hardening for the BPF JIT compiler. Supported are eBPF JIT backends.
 * Enabling hardening trades off performance, but can mitigate JIT spraying.
 * 0: disabled
 * 1: enabled
 * @param ar This is the structure containing all the issues enumy has found
 * @param cmdline This is the runtime arguments for enumy 
 */
static void check_bpf_jit_harden(All_Results *ar, Args *cmdline)
{
    char *loc = "/proc/sys/net/core/bpf_jit_harden";
    char *issue_name = "sysctl bpf_jit_harden";
    int id = 242;

    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, cmdline, id, loc, issue_name);
}

/**
 * /proc/sys/kernel/perf_event_paranoid
 * Controls use of the performance events system by unprivileged users (without CAP_SYS_ADMIN). The default value is 2.
 * -1: Allow use of (almost) all events by all users. Ignore mlock limit after perf_event_mlock_kb without CAP_IPC_LOCK.
 *  0: Disallow ftrace function tracepoint by users without CAP_SYS_ADMIN. Disallow raw tracepoint access by users without CAP_SYS_ADMIN.
 *  1: Disallow CPU event access by users without CAP_SYS_ADMIN.
 *  2: Disallow kernel profiling by users without CAP_SYS_ADMIN.
 * @param ar This is the structure containing all the issues enumy has found
 * @param cmdline This is the runtime arguments for enumy 
 */
static void check_event_parranoid(All_Results *ar, Args *cmdline)
{
    char *loc = "/proc/sys/kernel/perf_event_paranoid";
    char *issue_name = "sysctl perf_event_paranoid";
    int id = 243;

    if (check_location_exists(loc) && read_proc_int(loc) == -1)
        add_medium_issue(ar, cmdline, id, loc, issue_name);
}

/**
 * /proc/sys/kernel/core_pattern
 * Should be set to |/bin/false to disable core dumps 
 * @param ar This is the structure containing all the issues enumy has found
 * @param cmdline This is the runtime arguments for enumy 
 */
static void check_core_pattern(All_Results *ar, Args *cmdline)
{
    char *loc = "/proc/sys/kernel/core_pattern";
    char *issue_name = "sysctl core_pattern";
    int id = 244;
    int ch;
    char buf[MAXSIZE];
    int buf_loc = 0;

    if (!check_location_exists(loc))
        return;

    FILE *fp = fopen(loc, "r");
    if (fp == NULL)
    {
        DEBUG_PRINT("Failed to read file at location -> %s\n", loc);
        return;
    }

    while (!feof(fp))
    {
        ch = fgetc(fp);
        if (ch == EOF)
        {
            break;
        }
        buf[buf_loc] = (char)ch;
        buf_loc++;
    }

    buf[buf_loc] = '\0';
    fclose(fp);

    if (strstr("/false", buf) == NULL)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(loc, new_result);
        set_issue_name(issue_name, new_result);
        set_other_info("", new_result);
        add_new_result_medium(new_result, ar, cmdline);
    }
}

/**
 * /proc/sys/kernel/dmesg_restrict
 * 0: No restrictions
 * 1: users must have CAP_SYSLOG to use dmesg
 * @param ar This is the structure containing all the issues enumy has found
 * @param cmdline This is the runtime arguments for enumy 
 */
static void check_dmesg_restrict(All_Results *ar, Args *cmdline)
{
    char *loc = "/proc/sys/kernel/dmesg_restrict";
    char *issue_name = "sysctl dmesg_restrict";
    int id = 245;

    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, cmdline, id, loc, issue_name);
}

/**
 * /proc/sys/fs/protected_hardlinks
 * 0: hardlink creation behavior is unrestricted.
 * 1: hardlinks cannot be created by users if they do not already own the source file, or do not have read/write access to it.
 * @param ar This is the structure containing all the issues enumy has found
 * @param cmdline This is the runtime arguments for enumy 
 */
static void check_protected_hardlinks(All_Results *ar, Args *cmdline)
{
    char *loc = "/proc/sys/fs/protected_hardlinks";
    char *issue_name = "sysctl protected_hardlinks";
    int id = 246;

    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, cmdline, id, loc, issue_name);
}

/**
 * /proc/sys/fs/protected_softlinks
 * 0: softlink creation behavior is unrestricted.
 * 1: softlinks cannot be created by users if they do not already own the source file, or do not have read/write access to it.
 * @param ar This is the structure containing all the issues enumy has found
 * @param cmdline This is the runtime arguments for enumy 
 */
static void check_protected_symlinks(All_Results *ar, Args *cmdline)
{
    char *loc = "/proc/sys/fs/protected_softlinks";
    char *issue_name = "sysctl protected_softlinks";
    int id = 247;

    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, cmdline, id, loc, issue_name);
}

/**
 * /proc/sys/net/ipv4/tcp_syncookies
 * 0: disabled 
 * 1: enabled (should be enabled to prevent syn flooding)
 * @param ar This is the structure containing all the issues enumy has found
 * @param cmdline This is the runtime arguments for enumy 
 */
static void check_ipv4_tcp_syncookies(All_Results *ar, Args *cmdline)
{
    char *loc = "/proc/sys/net/ipv4/tcp_syncookies";
    char *issue_name = "sysctl tcp_syncookies";
    int id = 248;

    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, cmdline, id, loc, issue_name);
}

/**
 * /proc/sys/net/ipv4/ip_forward
 * IP forwarding permits the kernel to forward packets from one network interface to another.
 * The ability to forward packets between two networks is only appropriate for systems acting as routers.
 * Should be set to zero
 * @param ar This is the structure containing all the issues enumy has found
 * @param cmdline This is the runtime arguments for enumy 
 */
static void check_ipv4_ip_forward(All_Results *ar, Args *cmdline)
{
    char *loc = "/proc/sys/net/ipv4/ip_forward";
    char *issue_name = "sysctl ip_forward";
    int id = 249;

    if (check_location_exists(loc) && read_proc_int(loc) != 0)
        add_medium_issue(ar, cmdline, id, loc, issue_name);
}

/**
 * /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
 * Prevents bogus ICMP messesages being log, an attacker could use this cause log rotation 
 * This should be enabled with the value 1.
 * @param ar This is the structure containing all the issues enumy has found
 * @param cmdline This is the runtime arguments for enumy 
 */
static void check_ipv4_icmp_ignore_bogus_error_response(All_Results *ar, Args *cmdline)
{
    char *loc = "/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses";
    char *issue_name = "sysctl icmp_ignore_bogus_error_responses";
    int id = 250;

    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, cmdline, id, loc, issue_name);
}

/**
 * /proc/sys/net/ipv4/conf/all/accept_source_route
 * Do not accept source routed packets. Attackers can use source routing to generate traffic pretendin
 * to originate from inside your network, but that is actually routed back along the path from which it came,
 * so attackers can compromise your network
 * Should be set to zero
 * @param ar This is the structure containing all the issues enumy has found
 * @param cmdline This is the runtime arguments for enumy 
 */
static void check_ipv4_accept_source_route(All_Results *ar, Args *cmdline)
{
    char *loc = "/proc/sys/net/ipv4/conf/all/accept_source_route";
    char *issue_name = "sysctl accept_source_route";
    int id = 251;

    if (check_location_exists(loc) && read_proc_int(loc) != 0)
        add_medium_issue(ar, cmdline, id, loc, issue_name);
}

/**
 * /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
 * This disables response to ICMP broadcasts and will prevent Smurf attacks.
 * The Smurf attack works by sending an ICMP type 0 (ping) message to the broadcast address of a network. 
 * Typically the attacker will use a spoofed source address.
 * All the computers on the network will respond to the ping message and thereby flood the host at the spoofed source address.
 * This should be enabled with 1.
 * @param ar This is the structure containing all the issues enumy has found
 * @param cmdline This is the runtime arguments for enumy 
 */
static void check_ipv4_echo_ignore_broadcasts(All_Results *ar, Args *cmdline)
{
    char *loc = "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts";
    char *issue_name = "sysctl icmp_echo_ignore_broadcasts";
    int id = 252;

    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, cmdline, id, loc, issue_name);
}

/**
 * /proc/sys/kernel/randomize_va_space
 * Aslr should be enabled to the value 2
 * @param ar This is the structure containing all the issues enumy has found
 * @param cmdline This is the runtime arguments for enumy 
 */
static void check_randomized_va_space(All_Results *ar, Args *cmdline)
{
    char *loc = "/proc/sys/kernel/randomize_va_space";
    char *issue_name = "sysctl randomize_va_space";
    int id = 253;

    if (check_location_exists(loc) && read_proc_int(loc) != 2)
        add_medium_issue(ar, cmdline, id, loc, issue_name);
}

static bool check_location_exists(char *location)
{
    return (access(location, F_OK) != -1);
}

static int read_proc_int(char *location)
{
    FILE *fp = fopen(location, "r");
    int ch;
    char buf[MAXSIZE];
    int buf_loc = 0;

    if (fp == NULL)
    {
        DEBUG_PRINT("Failed to read file at location -> %s\n", location);
        return BAD_READ;
    }

    while (!feof(fp))
    {
        ch = fgetc(fp);
        if (ch == EOF)
            break;

        buf[buf_loc] = (char)ch;
        buf_loc++;
    }

    buf[buf_loc] = '\0';

    fclose(fp);
    return atoi(buf);
}

static void add_medium_issue(All_Results *ar, Args *cmdline, int id, char *loc, char *issue_name)
{
    Result *new_result = create_new_issue();
    set_id_and_desc(id, new_result);
    set_issue_location(loc, new_result);
    set_issue_name(issue_name, new_result);
    set_other_info("", new_result);
    add_new_result_medium(new_result, ar, cmdline);
}