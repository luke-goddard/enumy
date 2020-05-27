/* 
    Full credit to https://gtfobins.github.io/ for the list of files 
    I've just copied this list and automated the scanning process 
*/

#include "debug.h"
#include "file_system.h"
#include "scan.h"
#include "elf_parsing.h"

#include <stdio.h>
#include <string.h>

#define BUILD_TOOLS 0
#define SHELL 1
#define REVERSE_SHELL 2
#define BIND_SHELL 3
#define NON_INTERACTIVE_BIND_SHELL 4
#define FILE_UPLOAD 5
#define FILE_READ 6
#define FILE_WRITE 7
#define LIB_LOAD 8
#define FILE_DOWNLOAD 9

#define TOTAL_CATEGORY_COUNT 10

#define INFO 0
#define LOW 1
#define MED 2
#define HIGH 3

/* ============================ PROTOTYPES ============================== */

void lotl_scan(File_Info *fi, All_Results *ar, Args *cmdline);

static void search_implementation(int tool_type, File_Info *fi, All_Results *ar, Args *cmdline);
static void report_issue(File_Info *fi, All_Results *ar, Args *cmdline, int type);

/* ============================ CONSTANTS ============================== */

/* Issue description messages */
const char *BuildToolsIssueDesc = "Development tool found";
const char *ShellIssueDesc = "Executable that can breakout of restricted shells found";
const char *RevShellIssueDesc = "Executable capable of spawning reverse shells found";
const char *BindShellIssueDesc = "Executable capable of spawning bind shells found";
const char *NonInterShellIssueDesc = "Executable capable of non interactive bind shells found";
const char *FileUploadIssueDesc = "Executable capable of exfiltrating files off the network found";
const char *FileReadIssueDesc = "Executable capable of reading arbitrary files as root found";
const char *FileWriteIssueDesc = "Executable capable of writing arbitrary files as root found";
const char *LibLoadIssueDesc = "Executable capable of loading shared libaries as root found";
const char *FileDownloadIssueDesc = "Executable capable of exfiltrating files off the network found";

/* Build tools should not be found on production environments */
const char *BuildTools[] = {
    "as", "addr2line", "ar", "cc", "clang", "c++filt", "dlltool", "gold", "gprof", "ld",
    "nlmconv", "objcopy", "objdump", "ranlib", "readelf", "size", "strings", "strip"};

/* These programs can be used to break out of a restricted shell */
const char *ShellTools[] = {
    "apt-get", "apt", "ash", "awk", "bash", "bundler", "busctl", "busybox", "byebug", "cobc",
    "cpan", "cpulimit", "crash", "csh", "dash", "dmesg", "docker", "dpkg", "easy_install",
    "eb", "ed", "emacs", "env", "expect", "facter", "find", "flock", "ftp", "gawk", "gcc",
    "gdb", "gem", "gimp", "git", "gtester", "iftop", "ionice", "irb", "jjs", "journalctl",
    "jrunscript", "ksh", "ld.so", "less", "logsave", "ltrace", "lua", "mail", "make", "man",
    "mawk", "more", "mysql", "nano", "nawk", "nice", "nmap", "node", "nohup", "nroff", "nsenter",
    "pdb", "perl", "pg", "php", "pic", "pico", "pip", "pry", "puppet", "python", "rake", "rlwrap",
    "rpm", "rpmquery", "rsync", "ruby", "run-mailcap", "run-parts", "rvim", "scp", "screen",
    "script", "sed", "service", "setarch", "sftp", "smbclient", "socat", "sqlite3", "ssh",
    "start-stop-daemon", "stdbuf", "strace", "tar", "taskset", "tclsh", "telnet", "time",
    "timeout", "tmux", "top", "unshare", "valgrind", "vi", "vim", "watch", "wish", "xargs",
    "zip", "zsh", "zypper"};

/* These tools can be used to spawn a reverse shell */
const char *RevShellTools[] = {
    "bash", "cpan", "easy_install", "gdb", "gimp", "irb", "jjs", "jrunscript", "ksh", "nc",
    "node", "openssl", "perl", "php", "pip", "python", "ruby", "rvim", "socat", "telnet",
    "vim", "vi"};

/* These tools can be used to spawn a bind shell */
const char *BindShellTools[] = {
    "nc", "node", "socat"};

/* These toools can be used to spawn a non interactive bind shell */
const char *NonInterShellTools[] = {
    "awk", "gawk", "lua", "nawk", "nmap", "rvim", "vim"};

/* These tools can be used to upload arbitrary files to the target system */
const char *FileUploadTools[] = {
    "bash", "busybox", "cancel", "cpan", "curl", "easy_install", "finger", "ftp", "gdb",
    "gimp", "irb", "ksh", "lua", "nc", "nmap", "openssl", "php", "pip", "python", "restic",
    "rlogin", "ruby", "rvim", "scp", "sftp", "smbclient", "socat", "ssh", "tar", "tftp",
    "vim", "wget", "whoami"};

/* These tools can be used to read arbitary files assuming that it has SUID */
const char *FileReadTools[] = {
    "arp", "awk", "base32", "base64", "bash", "busybox", "cat", "cp", "curl", "cut", "date",
    "dd", "dialog", "diff", "dmesg", "docker", "easy_install", "ed", "emacs", "eqn", "expand",
    "file", "fmt", "fold", "gawk", "gdb", "genisoimage", "gimp", "grep", "hd", "head",
    "hexdump", "highlight", "iconv", "ip", "irb", "jjs", "jq", "jrunscript", "ksh", "ksshell",
    "less", "look", "lua", "lwp-request", "man", "mawk", "more", "mtr", "nano", "nawk", "nl",
    "nmap", "od", "openssl", "pg", "pico", "pip", "puppet", "python", "readelf", "red",
    "redcarpet", "ruby", "run-mailcap", "rvim", "sed", "shuf", "soelim", "sort", "sqlite3",
    "ssh", "strings", "tac", "tail", "tar", "ul", "unexpand", "uniq", "uudecode", "uuencode",
    "vi", "vim", "xargs", "xxd", "xz", "yelp", "zsoelim"};

/* These tools can be used to write arbitrary files assuming that it has SUID */
const char *FileWriteTools[] = {
    "ash", "awk", "bash", "busybox", "cp", "csh", "dash", "dd", "docker", "easy_install",
    "ed", "emacs", "gawk", "gdb", "gimp", "iconv", "irb", "jjs", "jrunscript", "ksh",
    "less", "lua", "make", "mawk", "nano", "nawk", "nmap", "openssl", "pico", "pip", "puppet",
    "python", "red", "rlwrap", "ruby", "run-mailcap", "rvim", "screen", "script", "sed",
    "shuf", "sqlite3", "tar", "tee", "vi", "vim", "xxd"};

/* These tools can be used to load shared objects assuming that it has SUID */
const char *LibLoadTools[] = {
    "bash", "easy_install", "gdb", "gimp", "irb", "mysql", "openssl", "pip", "python",
    "ruby", "rvim", "vim"};

/* These tools can be used to download arbitrary files from a remote network */
const char *FileDownloadTools[] = {
    "bash", "cpan", "curl", "easy_install", "finger", "ftp", "gdb", "gimp", "irb", "jjs",
    "jrunscript", "ksh", "lua", "lwp-download", "nc", "nmap", "openssl", "php", "pip",
    "python", "ruby", "rvim", "scp", "sftp", "smbclient", "socat", "ssh", "tar", "tftp",
    "vim", "wget", "whois"};

/* List of pointers to const char * arrays containg the interesting files that we're searching for */
void *TotalTools[] = {
    &BuildTools, &ShellTools, &RevShellTools, &BindShellTools, &NonInterShellTools,
    &FileUploadTools, &FileReadTools, &FileWriteTools, &LibLoadTools, &FileDownloadTools};

/* ============================ FUNCTIONS ============================== */

/**
 * Entrypoint to the living off the land scan
 * @param fi This is the current file that is being scaned 
 * @param ar This is a struct containing all of the results 
 * @param cmdline This is the run time arguments
 */
void lotl_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    if (!has_executable(fi))
        return;

    /* Scans that don't require the current file to be SUID */
    search_implementation(BUILD_TOOLS, fi, ar, cmdline);
    search_implementation(SHELL, fi, ar, cmdline);
    search_implementation(REVERSE_SHELL, fi, ar, cmdline);
    search_implementation(BIND_SHELL, fi, ar, cmdline);
    search_implementation(NON_INTERACTIVE_BIND_SHELL, fi, ar, cmdline);
    search_implementation(FILE_UPLOAD, fi, ar, cmdline);
    search_implementation(FILE_DOWNLOAD, fi, ar, cmdline);

    if (!has_suid(fi))
        return;

    /* Scans that do require the current file to be SUID */
    search_implementation(FILE_WRITE, fi, ar, cmdline);
    search_implementation(FILE_READ, fi, ar, cmdline);
    search_implementation(LIB_LOAD, fi, ar, cmdline);
}

/* ============================ STATIC FUNCTIONS ============================== */

/**
 * Finds the consts char * array realated to the current scan and then reports
 * the file as an issue if it matches
 * @param type This is the type of scan that is defined above  
 * @param fi This is the current file that is being scaned 
 * @param ar This is a struct containing all of the results 
 * @param cmdline This is the run time arguments
 */
static void search_implementation(int tool_type, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int const_array_size;

    /* Check that the type exists */
    if (tool_type < 0 || tool_type > TOTAL_CATEGORY_COUNT)
    {
        DEBUG_PRINT("Recived unknown type %i inside of lotl_scan\n", tool_type);
        return;
    }

    /* Set the array to the const char * pointer that is related to the current scan type */
    const char **const_array = TotalTools[tool_type];

    /* Get the size of the array we are going to search */
    /* There must be a better way to do this but its late */

    if (tool_type == BUILD_TOOLS)
        const_array_size = sizeof BuildTools / sizeof(BuildTools[0]);

    else if (tool_type == SHELL)
        const_array_size = sizeof ShellTools / sizeof(ShellTools[0]);

    else if (tool_type == REVERSE_SHELL)
        const_array_size = sizeof RevShellTools / sizeof(RevShellTools[0]);

    else if (tool_type == BIND_SHELL)
        const_array_size = sizeof BindShellTools / sizeof(BindShellTools[0]);

    else if (tool_type == NON_INTERACTIVE_BIND_SHELL)
        const_array_size = sizeof NonInterShellTools / sizeof(NonInterShellTools[0]);

    else if (tool_type == FILE_UPLOAD)
        const_array_size = sizeof FileUploadTools / sizeof(FileUploadTools[0]);

    else if (tool_type == FILE_DOWNLOAD)
        const_array_size = sizeof FileDownloadTools / sizeof(FileDownloadTools[0]);

    else if (tool_type == FILE_WRITE)
        const_array_size = sizeof FileWriteTools / sizeof(FileWriteTools[0]);

    else if (tool_type == FILE_READ)
        const_array_size = sizeof FileReadTools / sizeof(FileReadTools[0]);

    else if (tool_type == LIB_LOAD)
        const_array_size = sizeof LibLoadTools / sizeof(LibLoadTools[0]);

    /* Itterate through the files we're searching for */
    for (int i = 0; i < const_array_size; i++)
    {
        /* if current file matches it then report it  as an issue */
        if ((const_array[i][0] == fi->name[0]) && (strcmp(const_array[i], fi->name) == 0))
            report_issue(fi, ar, cmdline, tool_type);
    }
}

/**
 * Wrapper function to report an issue 
 * @param fi This is the files information 
 * @param ar This a struct containing the linked list of enumy findings 
 * @param cmdline This is the runtime arguments 
 * @param type This is the type of issue to raise
 */
static void report_issue(File_Info *fi, All_Results *ar, Args *cmdline, int type)
{
    if (type == BUILD_TOOLS)
        add_issue(MED, 0, fi->location, ar, cmdline, (char *)BuildToolsIssueDesc, "");

    else if (type == SHELL)
        add_issue(LOW, 0, fi->location, ar, cmdline, (char *)ShellIssueDesc, "");

    else if (type == REVERSE_SHELL)
        add_issue(MED, 0, fi->location, ar, cmdline, (char *)RevShellIssueDesc, "");

    else if (type == BIND_SHELL)
        add_issue(MED, 0, fi->location, ar, cmdline, (char *)BindShellIssueDesc, "");

    else if (type == NON_INTERACTIVE_BIND_SHELL)
        add_issue(LOW, 0, fi->location, ar, cmdline, (char *)NonInterShellIssueDesc, "");

    else if (type == FILE_UPLOAD)
        add_issue(LOW, 0, fi->location, ar, cmdline, (char *)FileUploadIssueDesc, "");

    else if (type == FILE_READ)
        add_issue(HIGH, 0, fi->location, ar, cmdline, (char *)FileReadIssueDesc, "");

    else if (type == FILE_WRITE)
        add_issue(HIGH, 0, fi->location, ar, cmdline, (char *)FileWriteIssueDesc, "");

    else if (type == LIB_LOAD)
        add_issue(HIGH, 0, fi->location, ar, cmdline, (char *)LibLoadIssueDesc, "");

    else if (type == FILE_DOWNLOAD)
        add_issue(LOW, 0, fi->location, ar, cmdline, (char *)FileDownloadIssueDesc, "");
}