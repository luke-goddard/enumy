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

void sys_scan(All_Results *ar);

static bool check_location_exists(char *location);
static int read_proc_int(char *location);

static void check_suid_dumpable(All_Results *ar);
static void check_core_uses_pid(All_Results *ar);
static void check_ctrl_alt_delete(All_Results *ar);
static void check_kptr_restrict(All_Results *ar);
static void check_namespaces(All_Results *ar);
static void check_ptrace_scope(All_Results *ar);
static void check_kexec_load(All_Results *ar);
static void check_bpf_disabled(All_Results *ar);
static void check_bpf_jit_harden(All_Results *ar);
static void check_event_parranoid(All_Results *ar);
static void check_core_pattern(All_Results *ar);
static void check_dmesg_restrict(All_Results *ar);
static void check_protected_hardlinks(All_Results *ar);
static void check_protected_symlinks(All_Results *ar);
static void check_ipv4_tcp_syncookies(All_Results *ar);
static void check_ipv4_ip_forward(All_Results *ar);
static void check_ipv4_icmp_ignore_bogus_error_response(All_Results *ar);
static void check_ipv4_accept_source_route(All_Results *ar);
static void check_randomized_va_space(All_Results *ar);
static void check_ipv4_echo_ignore_broadcasts(All_Results *ar);
static void add_medium_issue(All_Results *ar, char *loc, char *issue_name);

/* ============================ FUNCTIONS ============================== */

/**
 * This scan will look at kerenl parameters in /proc/sys
 * The values of these parameters can have major implications on the security
 * of product machines for example, ASLR should always be enabled on modern
 * systems. There are plenty of other parameters that would probably be ignored 
 * unless you're doing a very in depth pentest
 * @param ar This is the structure that holds the link lists with the results 
 */
void sys_scan(All_Results *ar)
{
    check_suid_dumpable(ar);
    check_core_uses_pid(ar);
    check_ctrl_alt_delete(ar);
    check_kptr_restrict(ar);
    check_namespaces(ar);
    check_ptrace_scope(ar);
    check_kexec_load(ar);
    check_bpf_disabled(ar);
    check_bpf_jit_harden(ar);
    check_event_parranoid(ar);
    check_core_pattern(ar);
    check_dmesg_restrict(ar);
    check_protected_hardlinks(ar);
    check_protected_symlinks(ar);
    check_ipv4_tcp_syncookies(ar);
    check_ipv4_ip_forward(ar);
    check_ipv4_icmp_ignore_bogus_error_response(ar);
    check_ipv4_accept_source_route(ar);
    check_ipv4_echo_ignore_broadcasts(ar);
    check_randomized_va_space(ar);
}

/* ============================ STATIC FUNCTIONS ============================== */

/**
 * /proc/sys/kernel/fs/suid_dumpable
 *0. (default) - traditional behaviour. Any process which has changed privilege levels or is execute only will not be dumped.
 *1. (debug) - all processes dump core when possible. The core dump is owned by the current user and no security is applied.
 *             This is intended for system debugging situations only. Ptrace is unchecked. This is insecure as it allows regular
 *             users to examine the memory contents of privileged processes.
 *2. (suidsafe) - any binary which normally would not be dumped is dumped anyway, but only if the “core_pattern” kernel sysctl
                  is set to either a pipe handler or a fully qualified path. (For more details on this limitation,
                  see CVE-2006-2451.) This mode is appropriate when administrators are attempting to debug problems in
                  a normal environment, and either have a core dump pipe handler that knows to treat privileged core dumps
                  with care, or specific directory defined for catching core dumps. If a core dump happens without a pipe handler
                  or fully qualifid path, a message will be emitted to syslog warning about the lack of a correct setting.
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_suid_dumpable(All_Results *ar)
{
    char *loc = "/proc/sys/fs/suid_dumpable";
    if (check_location_exists(loc) && read_proc_int(loc) != 0)
        add_medium_issue(ar, loc, "Coredumps on SUID files are enabled");
}

/**
 * The default coredump filename is “core”. By setting core_uses_pid to 1, the coredump filename becomes core.PID.
 * If core_pattern does not include “%p” (default does not) and core_uses_pid is set, then .PID will be appended to the filename.
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_core_uses_pid(All_Results *ar)
{
    char *loc = "/proc/sys/kernel/core_uses_pid";
    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, loc, "Coredumps files generate save PID");
}

/**
 * /proc/sys/kernel/ctrl-alt-del
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_ctrl_alt_delete(All_Results *ar)
{
    char *loc = "/proc/sys/kernel/ctrl-alt-del";
    if (check_location_exists(loc) && read_proc_int(loc) != 0)
        add_medium_issue(ar, loc, "Ctrl+Alt+Delete is not sent to init(1)");
}

/**
 * /proc/sys/kernel/kptr_restrict
 * 0: When kptr_restrict is set to 0 (the default) the address is hashed before printing. (This is the equivalent to %p.)
 * 1: kernel pointers printed using the %pK format specifier will be replaced with 0's unless the user has CAP_SYSLOG 
 *    and effective user and group ids are equal to the real ids
 * 2: Kernel pointers are always 0 when printed 
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_kptr_restrict(All_Results *ar)
{
    char *loc = "/proc/sys/kernel/kptr_restrict";
    if (check_location_exists(loc) && read_proc_int(loc) != 2)
        add_medium_issue(ar, loc, "sysctl kptr_restrict disabled");
}

/**
 * /proc/sys/user/max_user_namespaces
 * The maximum number of user namespaces that any user in the current user name space may create 
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_namespaces(All_Results *ar)
{
    char *loc = "/proc/sys/user/max_user_namespaces";
    if (check_location_exists(loc) && read_proc_int(loc) != 0)
        add_medium_issue(ar, loc, "sysctl namespaces enabled");
}

/**
 * /proc/sys/kernel/yama/ptrace_scope
 * 0: all processes can be debugged, as long as they have same uid. This is the classical way of how ptracing worked.
 * 1: only a parent process can be debugged.
 * 2: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
 * 3: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_ptrace_scope(All_Results *ar)
{
    char *loc = "/proc/sys/kernel/yama/ptrace_scope";
    if (check_location_exists(loc) && read_proc_int(loc) != 3)
        add_issue(MEDIUM, CTF, loc, ar, "sysctl ptrace is configured insecurly", "");
}

/**
 * /proc/sys/kernel/kexec_load_disabled
 * 0: (Default) kexec_load syscall enabled
 * 1: kexec_load syscall disabled (cannot be re-enabled)
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_kexec_load(All_Results *ar)
{
    char *loc = "/proc/sys/kernel/kexec_load_disabled";
    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, loc, "sysctl kexec_load_disabled");
}

/**
 * /proc/sys/kernel/unprivileged_bpf_disabled
 * 0: bpf() syscall for unprivileged users is enabled
 * 1: bpf() syscall restricted to privileged users
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_bpf_disabled(All_Results *ar)
{
    char *loc = "/proc/sys/kernel/unprivileged_bpf_disabled";
    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, loc, "sysctl unprivileged_bpf_disabled");
}

/**
 * /proc/sys/net/core/bpf_jit_harden
 * This enables hardening for the BPF JIT compiler. Supported are eBPF JIT backends.
 * Enabling hardening trades off performance, but can mitigate JIT spraying.
 * 0: disabled
 * 1: enabled
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_bpf_jit_harden(All_Results *ar)
{
    char *loc = "/proc/sys/net/core/bpf_jit_harden";
    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, loc, "sysctl bpf_jit_harden is disabled");
}

/**
 * /proc/sys/kernel/perf_event_paranoid
 * Controls use of the performance events system by unprivileged users (without CAP_SYS_ADMIN). The default value is 2.
 * -1: Allow use of (almost) all events by all users. Ignore mlock limit after perf_event_mlock_kb without CAP_IPC_LOCK.
 *  0: Disallow ftrace function tracepoint by users without CAP_SYS_ADMIN. Disallow raw tracepoint access by users without CAP_SYS_ADMIN.
 *  1: Disallow CPU event access by users without CAP_SYS_ADMIN.
 *  2: Disallow kernel profiling by users without CAP_SYS_ADMIN.
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_event_parranoid(All_Results *ar)
{
    char *loc = "/proc/sys/kernel/perf_event_paranoid";
    if (check_location_exists(loc) && read_proc_int(loc) == -1)
        add_medium_issue(ar, loc, "sysctl perf_event_paranoid");
}

/**
 * /proc/sys/kernel/core_pattern
 * Should be set to |/bin/false to disable core dumps 
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_core_pattern(All_Results *ar)
{
    char *loc = "/proc/sys/kernel/core_pattern";
    char buf[MAXSIZE];
    int buf_loc = 0;

    /* Make sure that the path exists */
    if (!check_location_exists(loc))
        return;

    /* Try and open the file */
    FILE *fp = fopen(loc, "r");
    if (fp == NULL)
    {
        DEBUG_PRINT("Failed to read file at location -> %s\n", loc);
        return;
    }

    /* Read the file character by character */
    while (!feof(fp))
    {
        int ch = fgetc(fp);
        if (ch == EOF)
            break;

        buf[buf_loc] = (char)ch;
        buf_loc++;
    }

    /* clean up */
    buf[buf_loc] = '\0';
    fclose(fp);

    /* See the file contained "/false" indicating that core dumps are disabled */
    if (strstr("/false", buf) == NULL)
        add_medium_issue(ar, loc, "sysctl core_pattern is not disabled");
}

/**
 * /proc/sys/kernel/dmesg_restrict
 * 0: No restrictions
 * 1: users must have CAP_SYSLOG to use dmesg
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_dmesg_restrict(All_Results *ar)
{
    char *loc = "/proc/sys/kernel/dmesg_restrict";
    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, loc, "sysctl dmesg_restrict has no restrictions");
}

/**
 * /proc/sys/fs/protected_hardlinks
 * 0: hardlink creation behavior is unrestricted.
 * 1: hardlinks cannot be created by users if they do not already own the source file, or do not have read/write access to it.
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_protected_hardlinks(All_Results *ar)
{
    char *loc = "/proc/sys/fs/protected_hardlinks";
    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, loc, "sysctl protected_hardlinks is not restricted");
}

/**
 * /proc/sys/fs/protected_softlinks
 * 0: softlink creation behavior is unrestricted.
 * 1: softlinks cannot be created by users if they do not already own the source file, or do not have read/write access to it.
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_protected_symlinks(All_Results *ar)
{
    char *loc = "/proc/sys/fs/protected_softlinks";
    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, loc, "sysctl protected_softlinks is unrestricted");
}

/**
 * /proc/sys/net/ipv4/tcp_syncookies
 * 0: disabled 
 * 1: enabled (should be enabled to prevent syn flooding)
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_ipv4_tcp_syncookies(All_Results *ar)
{
    char *loc = "/proc/sys/net/ipv4/tcp_syncookies";
    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, loc, "sysctl tcp_syncookies not enabled");
}

/**
 * /proc/sys/net/ipv4/ip_forward
 * IP forwarding permits the kernel to forward packets from one network interface to another.
 * The ability to forward packets between two networks is only appropriate for systems acting as routers.
 * Should be set to zero
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_ipv4_ip_forward(All_Results *ar)
{
    char *loc = "/proc/sys/net/ipv4/ip_forward";
    if (check_location_exists(loc) && read_proc_int(loc) != 0)
        add_medium_issue(ar, loc, "sysctl ip_forward is enabled");
}

/**
 * /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
 * Prevents bogus ICMP messesages being log, an attacker could use this cause log rotation 
 * This should be enabled with the value 1.
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_ipv4_icmp_ignore_bogus_error_response(All_Results *ar)
{
    char *loc = "/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses";
    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, loc, "sysctl icmp_ignore_bogus_error_responses is enabled");
}

/**
 * /proc/sys/net/ipv4/conf/all/accept_source_route
 * Do not accept source routed packets. Attackers can use source routing to generate traffic pretendin
 * to originate from inside your network, but that is actually routed back along the path from which it came,
 * so attackers can compromise your network
 * Should be set to zero
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_ipv4_accept_source_route(All_Results *ar)
{
    char *loc = "/proc/sys/net/ipv4/conf/all/accept_source_route";
    if (check_location_exists(loc) && read_proc_int(loc) != 0)
        add_medium_issue(ar, loc, "sysctl accept_source_route is accepted");
}

/**
 * /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
 * This disables response to ICMP broadcasts and will prevent Smurf attacks.
 * The Smurf attack works by sending an ICMP type 0 (ping) message to the broadcast address of a network. 
 * Typically the attacker will use a spoofed source address.
 * All the computers on the network will respond to the ping message and thereby flood the host at the spoofed source address.
 * This should be enabled with 1.
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_ipv4_echo_ignore_broadcasts(All_Results *ar)
{
    char *loc = "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts";
    if (check_location_exists(loc) && read_proc_int(loc) != 1)
        add_medium_issue(ar, loc, "sysctl icmp_echo_ignore_broadcast is not enabled");
}

/**
 * /proc/sys/kernel/randomize_va_space
 * Aslr should be enabled to the value 2
 * @param ar This is the structure containing all the issues enumy has found
 */
static void check_randomized_va_space(All_Results *ar)
{
    char *loc = "/proc/sys/kernel/randomize_va_space";

    if (check_location_exists(loc) && read_proc_int(loc) != 2)
        add_issue(HIGH, CTF, loc, ar, "Syscyl randomize_va_space (ASLR) is not securly configured", "");
}

static bool check_location_exists(char *location)
{
    return (access(location, F_OK) != -1);
}

/**
 * This function will read a file in /proc/sys 
 * The file at location should contain a single integer value and 
 * should not be with file that contain a string etc. 
 * @param location This is the location of the file to read
 */
static int read_proc_int(char *location)
{
    char buf[MAXSIZE];
    int buf_loc = 0;

    /* Try and open the file */
    FILE *fp = fopen(location, "r");
    if (fp == NULL)
    {
        DEBUG_PRINT("Failed to read file at location -> %s\n", location);
        return BAD_READ;
    }

    /* Read the file character by character */
    while (!feof(fp))
    {
        int ch = fgetc(fp);
        if (ch == EOF)
            break;

        buf[buf_loc] = (char)ch;
        buf_loc++;
    }

    buf[buf_loc] = '\0';

    /* clean up */
    fclose(fp);

    /* Return the integer value */
    return atoi(buf);
}

/**
 * Wrapper function to add the issue to the issue linked list 
 * @param ar All the results 
 * @param location This is location of the file 
 * @param issue_name This is the name to give the issue 
 */
static void add_medium_issue(All_Results *ar, char *loc, char *issue_name)
{
    add_issue(MEDIUM, AUDIT, loc, ar, issue_name, "");
}