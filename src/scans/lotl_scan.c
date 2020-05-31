/* 
    Full credit to https://gtfobins.github.io/ for the list of files 
    I've just copied this list and automated the scanning process 
*/

#include "debug.h"
#include "file_system.h"
#include "scan.h"
#include "elf_parsing.h"
#include "error_logger.h"

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

void lotl_scan(File_Info *fi, All_Results *ar);

static void search_implementation(int tool_type, File_Info *fi, All_Results *ar);
static void report_issue(File_Info *fi, All_Results *ar, int type);

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

/* Sizes of all the arrays stored in an array that can be accesd via the scan code */
unsigned int ToolsArraySizes[] = {
    sizeof BuildTools / sizeof(BuildTools[0]),
    sizeof ShellTools / sizeof(ShellTools[0]),
    sizeof RevShellTools / sizeof(RevShellTools[0]),
    sizeof BindShellTools / sizeof(BindShellTools[0]),
    sizeof NonInterShellTools / sizeof(NonInterShellTools[0]),
    sizeof FileUploadTools / sizeof(FileUploadTools[0]),
    sizeof FileReadTools / sizeof(FileReadTools[0]),
    sizeof FileWriteTools / sizeof(FileWriteTools[0]),
    sizeof LibLoadTools / sizeof(LibLoadTools[0]),
    sizeof FileDownloadTools / sizeof(FileDownloadTools[0])};

/* List of pointers to const char * arrays containg the interesting files that we're searching for */
void *TotalTools[] = {
    &BuildTools, &ShellTools, &RevShellTools, &BindShellTools, &NonInterShellTools,
    &FileUploadTools, &FileReadTools, &FileWriteTools, &LibLoadTools, &FileDownloadTools};

/* ============================ FUNCTIONS ============================== */

/**
 * (lotl) Living off the land is technique used by hackers to utilize files  
 * found on the system to reduce noise, increase stealth and perform useful tasks 
 * This scan will look for common files such as netcat, gcc etc that can be usful 
 * durning a pentest.
 * @param fi This is the current file that's going to be scanned 
 * @param ar This is the structure that holds the link lists with the results 
 */
void lotl_scan(File_Info *fi, All_Results *ar)
{
    if (!has_executable(fi))
        return;

    /* Scans that don't require the current file to be SUID */
    search_implementation(BUILD_TOOLS, fi, ar);
    search_implementation(SHELL, fi, ar);
    search_implementation(REVERSE_SHELL, fi, ar);
    search_implementation(BIND_SHELL, fi, ar);
    search_implementation(NON_INTERACTIVE_BIND_SHELL, fi, ar);
    search_implementation(FILE_UPLOAD, fi, ar);
    search_implementation(FILE_DOWNLOAD, fi, ar);

    if (!has_suid(fi))
        return;

    /* Scans that do require the current file to be SUID */
    search_implementation(FILE_WRITE, fi, ar);
    search_implementation(FILE_READ, fi, ar);
    search_implementation(LIB_LOAD, fi, ar);
}

/* ============================ STATIC FUNCTIONS ============================== */

/**
 * Finds the consts char * array realated to the current scan and then reports
 * the file as an issue if it matches
 * @param type This is the type of scan that is defined above  
 * @param fi This is the current file that is being scaned 
 * @param ar This is a struct containing all of the results 
 */
static void search_implementation(int tool_type, File_Info *fi, All_Results *ar)
{
    /* Check that the type exists */
    if (tool_type < 0 || tool_type > TOTAL_CATEGORY_COUNT - 1)
    {
        log_fatal("Programming error");
        log_fatal("Recived unknown search type for lotl scan");
        exit(EXIT_FAILURE);
    }

    /* Set the array to the const char * pointer that is related to the current scan type */
    unsigned int const_array_size = ToolsArraySizes[tool_type];
    const char **const_array = TotalTools[tool_type];

    /* Itterate through the files we're searching for */
    for (unsigned int i = 0; i < const_array_size; i++)
    {
        /* if current file matches it then report it  as an issue */
        if ((const_array[i][0] == fi->name[0]) && (strcmp(const_array[i], fi->name) == 0))
            report_issue(fi, ar, tool_type);
    }
}

/**
 * Wrapper function to report an issue 
 * @param fi This is the files information 
 * @param ar This a struct containing the linked list of enumy findings 
 * @param type This is the type of issue to raise
 */
static void report_issue(File_Info *fi, All_Results *ar, int type)
{
    if (type == BUILD_TOOLS)
        add_issue(MED, fi->location, ar, (char *)BuildToolsIssueDesc, "");

    else if (type == SHELL)
        add_issue(LOW, fi->location, ar, (char *)ShellIssueDesc, "");

    else if (type == REVERSE_SHELL)
        add_issue(MED, fi->location, ar, (char *)RevShellIssueDesc, "");

    else if (type == BIND_SHELL)
        add_issue(MED, fi->location, ar, (char *)BindShellIssueDesc, "");

    else if (type == NON_INTERACTIVE_BIND_SHELL)
        add_issue(LOW, fi->location, ar, (char *)NonInterShellIssueDesc, "");

    else if (type == FILE_UPLOAD)
        add_issue(LOW, fi->location, ar, (char *)FileUploadIssueDesc, "");

    else if (type == FILE_READ)
        add_issue(HIGH, fi->location, ar, (char *)FileReadIssueDesc, "");

    else if (type == FILE_WRITE)
        add_issue(HIGH, fi->location, ar, (char *)FileWriteIssueDesc, "");

    else if (type == LIB_LOAD)
        add_issue(HIGH, fi->location, ar, (char *)LibLoadIssueDesc, "");

    else if (type == FILE_DOWNLOAD)
        add_issue(LOW, fi->location, ar, (char *)FileDownloadIssueDesc, "");
}