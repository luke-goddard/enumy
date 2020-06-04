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
#include "error_logger.h"

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

int capabilities_scan(File_Info *fi, All_Results *ar);

static int check_cap(cap_t caps_for_file, cap_value_t search);

static void add_issue_wrapper(int issue_type, File_Info *fi, All_Results *ar, char *issue_name, char *cap_desc);
static void scan_cap(int severity, cap_t current, File_Info *fi, All_Results *ar, char *issue_name, cap_value_t find, const char *cap_desc);

/* ============================ CONSTS ============================== */

const char *CAP_AUDIT_CONTROL_INFO = "This binary can potentiall disable linux kernel auditing and change the rules";
const char *CAP_AUDIT_READ_INFO = "This binary can read from the auditing multicast netlink socket";
const char *CAP_AUDIT_WRITE_INFO = "This binary can write to the kernel auditing log";
const char *CAP_BLOCK_SUSPEND_INFO = "This binary can block system suspends";
const char *CAP_CHWON_INFO = "This binary can make changes to files UID's and GID's";
const char *CAP_DAC_OVERRIDE_INFO = "This binary can bypass read, write and execute permission checks";
const char *CAP_DAC_READ_SEARCH_INFO = "This binary can bypass read permission checks";
const char *CAP_FOWNER_INFO = "This binary can bypass checks that require a certain UID";
const char *CAP_FSETID_INFO = "This binary won't clear set user id and set group id mode bits when a file is modified";
const char *CAP_IPC_LOCK_INFO = "This binary has the ablitiy to lock memory";
const char *CAP_IPC_OWNER_INFO = "This binary has the ablitiy to bypass permission checks for operations on System V IPC objects";
const char *CAP_KILL_INFO = "This binary has the ablitiy to bypass permission checks for sendings signals";
const char *CAP_LEASE_INFO = "This binary can establish leases on arbitrary files";
const char *CAP_LINUX_IMMUTABLE_INFO = "This binary can set FS_APPEND_FL and FS_IMMUTABLE_FL inode flags";
const char *CAP_MAC_ADMIN_INFO = "This binary can allow MAC configurations or state changes (SMACK)";
const char *CAP_MAC_OVERRIDE_INFO = "This binary can override MAC";
const char *CAP_MKNOD_INFO = "This binary can create special files using mknod";
const char *CAP_NET_ADMIN_INFO = "This binary can perform various powerful networking related operations that would normally require root";
const char *CAP_NET_BIND_SERVICE_INFO = "This binary can bind to domain privileged ports (less than 1024)";
const char *CAP_NET_BROADCAST_INFO = "This binary can make socket broadcasts and listen to multicasts";
const char *CAP_NET_RAW_INFO = "This binary can use RAW and PACKET sockets and bind to any address for transparent proxying";
const char *CAP_SETGID_INFO = "This binary can make arbitrary manipulations of process GID's, forge GID's and write group ID mapping in a user namespace";
const char *CAP_SETFCAP_INFO = "This binary can set arbitrary linux capablities on files";
const char *CAP_SETPCAP_INFO = "This binary can if file capabilities are supported (i.e., since Linux 2.6.24): add any capability from the calling thread's bounding set to its inheritable set; drop capabilities from the bounding set(via prctl(2) PR_CAPBSET_DROP); make changes to the securebits flags. If file capabilities are not supported (i.e., kernels before Linux 2.6.24): grant or remove any capability in the caller's permitted capability set to or from any other process. (This property of CAP_SETPCAP is not available when the kernel is configured to support file capabilities, since CAP_SETPCAP has entirely different semantics for such kernels.) ";
const char *CAP_SETUID_INFO = "This binary can make arbitrary manuipulations of process UIDS, for UIDs while passing socket credentials via UNIX domain socketss and write user ID mapping in a user namespace";
const char *CAP_SYS_ADMIN_INFO = "* Perform a range of system administration operations including: quotactl(2), mount(2), umount(2), pivot_root(2), setdomainname(2)\n * perform privileged syslog(2) operations (since Linux 2.6.37, CAP_SYSLOG should be used to permit such operations); * perform VM86_REQUEST_IRQ vm86(2) command;\n * perform IPC_SET and IPC_RMID operations on arbitrary System V IPC objects;\n * override RLIMIT_NPROC resource limit;\n * perform operations on trusted and security Extended Attributes (see xattr(7)); * use lookup_dcookie(2);\n * use ioprio_set(2) to assign IOPRIO_CLASS_RT and (before\n Linux 2.6.25) IOPRIO_CLASS_IDLE I/O scheduling classes; * forge PID when passing socket credentials via UNIX domain sockets;\n * exceed /proc/sys/fs/file-max, the system-wide limit on the number of open files, in system calls that open files (e.g., accept(2), execve(2), open(2), pipe(2));\n * employ CLONE_* flags that create new namespaces with clone(2) and unshare(2) (but, since Linux 3.8, creating user namespaces does not require any capability);\n * call perf_event_open(2);\n * access privileged perf event information;\n * call setns(2) (requires CAP_SYS_ADMIN in the target namespace);\n * call fanotify_init(2);\n * call bpf(2);\n * perform privileged KEYCTL_CHOWN and KEYCTL_SETPERM keyctl(2) operations;\n * perform madvise(2) MADV_HWPOISON operation;\n * employ the TIOCSTI ioctl(2) to insert characters into the input queue of a terminal other than the caller's controlling terminal;\n * employ the obsolete nfsservctl(2) system call;\n * employ the obsolete bdflush(2) system call;\n * perform various privileged block-device ioctl(2) operations;\n * perform various privileged filesystem ioctl(2) operations;\n * perform privileged ioctl(2) operations on the /dev/random\n device (see random(4)); * install a seccomp(2) filter without first having to set the no_new_privs thread attribute;\n * modify allow/deny rules for device control groups;\n * employ the ptrace(2) PTRACE_SECCOMP_GET_FILTER operation to dump tracee's seccomp filters;\n * employ the ptrace(2) PTRACE_SETOPTIONS operation to suspend the tracee's seccomp protections (i.e., the PTRACE_O_SUSPEND_SECCOMP flag);\n * perform administrative operations on many device drivers.\n * Modify autogroup nice values by writing to /proc/[pid]/autogroup (see sched(7)).";
const char *CAP_SYS_BOOT_INFO = "This binary can use reboot() and kexec_load()";
const char *CAP_SYS_CHROOT_INFO = "This binary can use chroot and change mount namespaces using setns";
const char *CAP_SYS_MODULE_INFO = "This binary can load and unload kernel modules";
const char *CAP_SYS_PACCT_INFO = "This binary can use acct(2)";
const char *CAP_SYS_PTRACE_INFO = "This binary can trace abitrary process using ptrace, apply get_robust_list(), transfer data to or from memory and inspect processes using kcmp(2)";
const char *CAP_SYS_RAWIO_INFO = "This binary can perform IO opertions, access kcore and do lots of high privilaged IO opperations";
const char *CAP_SYS_TTY_CONFIG_INFO = "This binary can use vhangup(2) and ioctl(2) on virtual terminals";
const char *CAP_SYSLOG_INFO = "This binary can perform privileged syslog(2) operations and view kerenel addresses that are exposed via /proc";

/* ============================ FUNCTIONS ============================== */

/**
 * Linux systems have tried to discurage the use of SUID binaries because they're 
 * so dangerous if they're exploitable. One way Linux has combated this is with Linux 
 * capabilities. This gives the executable the option to a smaller subset of the powers
 * that root would have, minimizing the damage that can be done if the binary is exploited
 * @param fi This is the current file that's going to be scanned 
 * @param ar This is the structure that holds the link lists with the results 
 * @param args This is the runtime arguments needed for the scan
 */
int capabilities_scan(File_Info *fi, All_Results *ar)
{
    int findings = 0;
    cap_t cap;

    /* Check that the file is executable */
    if (!has_executable(fi))
        goto RET;

    /* Open the file */
    int fd = open(fi->location, O_RDONLY);
    if (fd == -1)
        goto RET;

    /* Populate the capablities */
    cap = cap_get_fd(fd);
    if (cap == NULL)
    {
        if (errno != ENODATA)
            log_error_errno_loc(ar, "Failed to populate capablities", fi->location, errno);
        goto CLOSE_RET;
    }

    /* HIGH issue serverity */
    scan_cap(HIGH, cap, fi, ar, "CAP_NET_BIND_SERVICE capablities enabled on file", CAP_NET_BIND_SERVICE, CAP_NET_BIND_SERVICE_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_DAC_READ_SEARCH capablities enabled on file", CAP_DAC_READ_SEARCH, CAP_DAC_READ_SEARCH_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_MAC_OVERRIDE capablities enabled on file", CAP_MAC_OVERRIDE, CAP_MAC_OVERRIDE_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_DAC_OVERRIDE capablities enabled on file", CAP_DAC_OVERRIDE, CAP_DAC_OVERRIDE_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_SYS_MODULE capablities enabled on file", CAP_SYS_MODULE, CAP_SYS_MODULE_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_SYS_PTRACE capablities enabled on file", CAP_SYS_PTRACE, CAP_SYS_PTRACE_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_SYS_CHROOT capablities enabled on file", CAP_SYS_CHROOT, CAP_SYS_CHROOT_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_SYS_ADMIN capablities enabled on file", CAP_SYS_ADMIN, CAP_SYS_ADMIN_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_MAC_ADMIN capablities enabled on file", CAP_MAC_ADMIN, CAP_MAC_ADMIN_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_NET_ADMIN capablities enabled on file", CAP_NET_ADMIN, CAP_NET_ADMIN_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_SETPCAP capablities enabled on file", CAP_SETPCAP, CAP_SETPCAP_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_NET_RAW capablities enabled on file", CAP_NET_RAW, CAP_NET_RAW_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_SETFCAP capablities enabled on file", CAP_SETFCAP, CAP_SETFCAP_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_FSETID capablities enabled on file", CAP_FSETID, CAP_FSETID_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_FOWNER capablities enabled on file", CAP_FOWNER, CAP_FOWNER_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_SETGID capablities enabled on file", CAP_SETGID, CAP_SETGID_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_SETUID capablities enabled on file", CAP_SETUID, CAP_SETUID_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_SYSLOG capablities enabled on file", CAP_SYSLOG, CAP_SYSLOG_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_CHOWN capablities enabled on file", CAP_CHOWN, CAP_CHWON_INFO);
    scan_cap(HIGH, cap, fi, ar, "CAP_LEASE capablities enabled on file", CAP_LEASE, CAP_LEASE_INFO);

    /* MEDIUM issue serverity */
    scan_cap(MEDIUM, cap, fi, ar, "CAP_AUDIT_CONTROL capablities enabled on file", CAP_AUDIT_CONTROL, CAP_AUDIT_CONTROL_INFO);
    scan_cap(MEDIUM, cap, fi, ar, "CAP_BLOCK_SUSPEND capablities enabled on file", CAP_BLOCK_SUSPEND, CAP_BLOCK_SUSPEND_INFO);
    scan_cap(MEDIUM, cap, fi, ar, "CAP_NET_BROADCAST capablities enabled on file", CAP_NET_BROADCAST, CAP_NET_BROADCAST_INFO);
    scan_cap(MEDIUM, cap, fi, ar, "CAP_AUDIT_WRITE capablities enabled on file", CAP_AUDIT_WRITE, CAP_AUDIT_WRITE_INFO);
    scan_cap(MEDIUM, cap, fi, ar, "CAP_AUDIT_READ capablities enabled on file", CAP_AUDIT_READ, CAP_AUDIT_READ_INFO);
    scan_cap(MEDIUM, cap, fi, ar, "CAP_IPC_OWNER capablities enabled on file", CAP_IPC_OWNER, CAP_IPC_OWNER_INFO);
    scan_cap(MEDIUM, cap, fi, ar, "CAP_SYS_PACCT capablities enabled on file", CAP_SYS_PACCT, CAP_SYS_PACCT_INFO);
    scan_cap(MEDIUM, cap, fi, ar, "CAP_IPC_LOCK capablities enabled on file", CAP_IPC_LOCK, CAP_IPC_LOCK_INFO);
    scan_cap(MEDIUM, cap, fi, ar, "CAP_KILL capablities enabled on file", CAP_KILL, CAP_KILL_INFO);

    /* LOW issue serverity */
    scan_cap(LOW, cap, fi, ar, "CAP_LINUX_IMMUTABLE capablities enabled on file", CAP_LINUX_IMMUTABLE, CAP_LINUX_IMMUTABLE_INFO);
    scan_cap(LOW, cap, fi, ar, "CAP_SYS_BOOT capablities enabled on file", CAP_SYS_BOOT, CAP_SYS_BOOT_INFO);
    scan_cap(LOW, cap, fi, ar, "CAP_MKNOD capablities enabled on file", CAP_MKNOD, CAP_MKNOD_INFO);

    cap_free(cap);

CLOSE_RET:
    close(fd);
RET:
    return findings;
}

/* ============================ STATIC FUNCTIONS ============================== */

/**
 * Wrapper function to check if the current file has a certain Linux capablity attached to it
 * @param issue_serverity If found how important is this linux capablity HIGH, MEDIUM, LOW
 * @param current_caps struct containing the current files linux capabilities
 * @param fi Struct containing the current files informationn
 * @param issue_name If found what description should we give the issue
 * @param cap_to_find this is the cap_value that we're searching for
 * @param cap_desc Summary of what the capablities do
 */
static void scan_cap(int issue_serverity, cap_t current_caps, File_Info *fi, All_Results *ar, char *issue_name, cap_value_t cap_to_find, const char *cap_desc)
{
    int cap_value = check_cap(current_caps, cap_to_find);

    if (cap_value)
        add_issue_wrapper(issue_serverity, fi, ar, issue_name, (char *)cap_desc);
}

/**
 * Wrapper function to short code to add new issue
 * @param issue_type If found how important is this linux capablity HIGH, MEDIUM, LOW
 * @param fi Struct containing the current files informationn
 * @param issue_name If found what description should we give the issue
 * @param cap_value This is the value of the capablity found
 * @param cap_desc Summary of what the capablities do
 */
static void add_issue_wrapper(int issue_type, File_Info *fi, All_Results *ar, char *issue_name, char *cap_desc)
{
    add_issue(issue_type, CTF, fi->location, ar, issue_name, cap_desc);
}

/**
 * Searches 'caps_for_file' for 'search' 
 * Effective ->     The effective set contains the capabilities that are currently active
 * Inheritable ->   The permitted set contains the capabilities that the process has the right to use.
 * Permited ->      The inheritable set contains the capabilities that can be inherited by children to the process
 * @param caps_for_file the files capabilities
 * @param search the capability that we're testing 
 * @return 0 If it does not have the capablities set
 * @return CAP_PERMITTED
 * @return CAP_INHERITABLE
 * @return CAP_EFFECTIVE
 */
static int check_cap(cap_t caps_for_file, cap_value_t search)
{
    cap_flag_t flag;                      /* values for this type are CAP_EFFECTIVE, CAP_INHERITABLE or CAP_PERMITTED */
    cap_flag_value_t value_p = CAP_CLEAR; /* valid values for this type are CAP_CLEAR (0) or CAP_SET (1) */

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