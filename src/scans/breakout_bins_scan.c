/* 
    This file will try and see if the an SUID/GUID binary is know to be insecure 
    with these permissions. I've just coppied from the following location

    https://gtfobins.github.io/
*/

#include "file_system.h"
#include "main.h"
#include "results.h"
#include "scan.h"

#include <string.h>

/* ============================ PROTOTYPES ============================== */

int break_out_binary_scan(File_Info *fi, All_Results *ar, Args *cmdline);
static void add_issue_wrapper(int id, char *name, File_Info *fi, All_Results *ar, Args *cmdline);
static bool compare_and_add_issue(int id, File_Info *fi, All_Results *ar, Args *cmdline, const char *search_str);

/* ============================ CONSTS ============================== */

const char *BreakOutBinaries[] = {
    "arp", "ash", "awk",                                                                               /* A */
    "base32", "base64", "bash", "bpftrace", "bundler", "busctl", "busybox", "byebug",                  /* B */
    "cancel", "cat", "chmod", "chown", "chroot", "cobc", "cp", "cpan", "cpulimit", "crash", "crontab", /* C */
    "csh", "curl", "cut",                                                                              /* C */
    "dash", "date", "dmidecode", "dd", "dialog", "diff", "dmesg", "dmsetup", "dnf", "docker",          /* D */
    "easy_install", "eb", "ed", "emacs", "env", "eqn", "expand", "expect",                             /* E */
    "facter", "file", "find", "finger", "flock", "fmt", "fold", "ftp",                                 /* F */
    "gawk", "gcc", "gdb", "gem", "genisoimage", "gimp", "git", "grep", "gtester",                      /* G */
    "hd", "head", "hexdump", "highlight",                                                              /* H */
    "iconv", "iftop", "ionice", "ip", "irb",                                                           /* I */
    "jjs", "journalctl", "jq", "jrunscript",                                                           /* J */
    "ksh", "kshell",                                                                                   /* K */
    "ld.so", "ldconfig", "less", "logsave", "look", "ltrace", "lua", "lwp-download", "lwp-request",    /* L */
    "mail", "make", "man", "mawk", "more", "mount", "mtr", "mv", "mysql",                              /* M */
    "nano", "nawk", "nc", "nice", "nl", "nmap", "node", "nohup", "nroff", "nsenter",                   /* N */
    "od", "openssl",                                                                                   /* O */
    "pdb", "perl", "pg", "php", "pic", "pico", "pip", "pry", "puppet", "python",                       /* P */
    "rake", "readelf", "red", "redcarpet", "restic", "rlogin", "rlwrap", "rpm",                        /* R */
    "rpmquery", "rsync", "ruby", "run-mailcap", "run-parts", "rvim",                                   /* R */
    "scp", "screen", "script", "sed", "service",                                                       /* S */
    "setarch", "sftp", "shuf", "smbclient", "socat", "soelim", "sort", "sqlite4", "ssh",               /* S */
    "start-stop-daemon", "stdbuff", "strace", "strings", "systemctl",                                  /* S */
    "tac", "tail", "tar", "taskset", "tclsh",                                                          /* T */
    "tcpdump", "tee", "telnet", "tftp", "time", "timeout", "tmux", "top",                              /* T */
    "ul", "unexpand", "uniq", "unshare", "uudecode", "uuencode",                                       /* U */
    "valgrind", "vi", "vim",                                                                           /* V */
    "watch", "wget", "whois", "wish",                                                                  /* W */
    "xarg", "xxd",                                                                                     /* W */
    "yelp", "yum",                                                                                     /* Y */
    "zip", "zsh", "zsoelim", "zypper"};                                                                /* Z */

/* ============================ FUNCTIONS ============================== */

/**
 * Should only be called if the file is known to be SUID or GUID or can be run as root e.g $sudo -l 
 * Compares the current file and tests to see if it matches a list of known breakout binaries
 * @param fi current files information 
 * @param ar struct containing all of the results enumy has foundd
 * @param cmdline list of cmdline arguments 
 */
int break_out_binary_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int const_array_size = sizeof BreakOutBinaries / sizeof(BreakOutBinaries[0]);
    int id = 0; // TODO REMOVE ME when hash id implemented

    /* Itterate through the list of SUID breakout binaries */
    for (int i = 0; i < const_array_size; i++)
    {
        /* They're in order so we can stop if the letter is greater than */
        if (fi->name[0] > BreakOutBinaries[i][0])
            return 0;

        if (
            fi->name[0] == BreakOutBinaries[i][0] &&
            compare_and_add_issue(id, fi, ar, cmdline, BreakOutBinaries[i]))
            return 1;
    }
    return 0;
}

/* ============================ STATIC FUNCTIONS ============================== */

/**
 * @param id issues new id 
 * @param name name of the breakout binary
 * @param fi file information for the file 
 * @param ar struct containing all the results that enumy has found on the system
 * @param cmdline a struct continaing the runtime arguments for enumy 
 * @param search_str the string to compare the current file's name against
 */
static bool compare_and_add_issue(int id, File_Info *fi, All_Results *ar, Args *cmdline, const char *search_str)
{
    if (strcmp(fi->name, search_str) == 0)
    {
        add_issue_wrapper(id, fi->name, fi, ar, cmdline);
        return true;
    }
    return false;
}

/**
 * Adds a findings to the ar.
 * @param id issues new id 
 * @param name name of the breakout binary
 * @param fi file information for the file 
 * @param ar struct containing all the results that enumy has found on the system
 * @param cmdline a struct continaing the runtime arguments for enumy 
 */
static void add_issue_wrapper(int id, char *name, File_Info *fi, All_Results *ar, Args *cmdline)
{
    char issue_name[MAXSIZE];
    char *base_name = " breakout binary found";

    strncpy(issue_name, name, MAXSIZE - strlen(base_name));
    strcat(issue_name, base_name);

    add_issue(HIGH, id, fi->location, ar, cmdline, issue_name, "None");
}