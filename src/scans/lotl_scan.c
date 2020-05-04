#include "debug.h"
#include "file_system.h"
#include "scan.h"
#include "elf_parsing.h"

#include <stdio.h>
#include <string.h>

void lotl_scan(File_Info *fi, All_Results *ar, Args *cmdline);

static void check_buildtools(File_Info *fi, All_Results *ar, Args *cmdline);
static void check_shell(File_Info *fi, All_Results *ar, Args *cmdline);
static void check_reverse_shell(File_Info *fi, All_Results *ar, Args *cmdline);
static void check_bind_shell(File_Info *fi, All_Results *ar, Args *cmdline);
static void check_non_interactive_bind_shell(File_Info *fi, All_Results *ar, Args *cmdline);
static void check_file_upload(File_Info *fi, All_Results *ar, Args *cmdline);
static void check_file_read(File_Info *fi, All_Results *ar, Args *cmdline);
static void check_file_write(File_Info *fi, All_Results *ar, Args *cmdline);
static void check_lib_load(File_Info *fi, All_Results *ar, Args *cmdline);
static void check_file_download(File_Info *fi, All_Results *ar, Args *cmdline);

static void report_buildtools(File_Info *fi, All_Results *ar, Args *cmdline);
static void report_shell(File_Info *fi, All_Results *ar, Args *cmdline);
static void report_reverse_shell(File_Info *fi, All_Results *ar, Args *cmdline);
static void report_bind_shell(File_Info *fi, All_Results *ar, Args *cmdline);
static void report_non_interactive_bind_shell(File_Info *fi, All_Results *ar, Args *cmdline);
static void report_file_upload(File_Info *fi, All_Results *ar, Args *cmdline);
static void report_file_read(File_Info *fi, All_Results *ar, Args *cmdline);
static void report_file_write(File_Info *fi, All_Results *ar, Args *cmdline);
static void report_lib_load(File_Info *fi, All_Results *ar, Args *cmdline);
static void report_file_download(File_Info *fi, All_Results *ar, Args *cmdline);

void lotl_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    check_buildtools(fi, ar, cmdline);
    check_shell(fi, ar, cmdline);
    check_reverse_shell(fi, ar, cmdline);
    check_bind_shell(fi, ar, cmdline);
    check_non_interactive_bind_shell(fi, ar, cmdline);
    check_file_upload(fi, ar, cmdline);
    check_file_download(fi, ar, cmdline);
    check_lib_load(fi, ar, cmdline);
    check_file_read(fi, ar, cmdline);
    check_file_write(fi, ar, cmdline);
}

/**
 * Checks to see if the current file name matches a file from the list of known build tools
 * @param fi This is current file that we are inspecting
 * @param ar This is a structure containing all of enumy's findings
 * @param cmdline This is the runtime commandline arguments 
 */
void check_buildtools(File_Info *fi, All_Results *ar, Args *cmdline)
{
    switch (fi->name[0])
    {
    case 'a':
        if (strcmp(fi->name, "as") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "addr2line") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "ar") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        break;
    case 'c':
        if (strcmp(fi->name, "cc") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "clang") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "c++filt") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        break;
    case 'd':
        if (strcmp(fi->name, "dlltool") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        break;
    case 'g':
        if (strcmp(fi->name, "gold") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "gprof") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        break;
    case 'l':
        if (strcmp(fi->name, "ld") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        break;
    case 'n':
        if (strcmp(fi->name, "nlmconv") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "nm") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        break;
    case 'o':
        if (strcmp(fi->name, "objcopy") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "objdump") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        break;
    case 'r':
        if (strcmp(fi->name, "ranlib") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "readelf") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        break;
    case 's':
        if (strcmp(fi->name, "size") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "strings") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "strip") == 0)
        {
            report_buildtools(fi, ar, cmdline);
            break;
        }
        break;
    }
}

/**
 * Checks to see if the current file name matches a file from the list of known breakouts
 * It can be used to break out from restricted environments by spawning an interactive system shell.
 * @param fi This is current file that we are inspecting
 * @param ar This is a structure containing all of enumy's findings
 * @param cmdline This is the runtime commandline arguments 
 */
void check_shell(File_Info *fi, All_Results *ar, Args *cmdline)
{
    switch (fi->name[0])
    {
    case 'a':
        if (strcmp(fi->name, "aria2c") == 0)
        {
            report_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'c':
        if (strcmp(fi->name, "crash") == 0)
        {
            report_shell(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "crontab") == 0)
        {
            report_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'n':
        if (strcmp(fi->name, "nohup") == 0)
        {
            report_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'p':
        if (strcmp(fi->name, "php") == 0)
        {
            report_shell(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "python") == 0)
        {
            report_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 's':
        if (strcmp(fi->name, "sed") == 0)
        {
            report_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 't':
        if (strcmp(fi->name, "tcpdump") == 0)
        {
            report_shell(fi, ar, cmdline);
            break;
        }
        break;
    }
}

/**
 * Checks to see if the current file name matches a file from the list of known breakouts
 * It can send back a reverse shell to a listening attacker to open a remote network access.
 * @param fi This is current file that we are inspecting
 * @param ar This is a structure containing all of enumy's findings
 * @param cmdline This is the runtime commandline arguments 
 */
void check_reverse_shell(File_Info *fi, All_Results *ar, Args *cmdline)
{
    switch (fi->name[0])
    {
    case 'a':
        if (strcmp(fi->name, "awk") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'b':
        if (strcmp(fi->name, "bash") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'c':
        if (strcmp(fi->name, "cpan") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'e':
        if (strcmp(fi->name, "easy_install") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'n':
        if (strcmp(fi->name, "nc") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "node") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "netcat") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "nmap") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "nawk") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'g':
        if (strcmp(fi->name, "gdb") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "gawk") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "gimp") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'i':
        if (strcmp(fi->name, "irb") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'j':
        if (strcmp(fi->name, "jjs") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "jrunscript") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'k':
        if (strcmp(fi->name, "ksh") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'o':
        if (strcmp(fi->name, "openssl") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'p':
        if (strcmp(fi->name, "php") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "pip") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "perl") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'r':
        if (strcmp(fi->name, "ruby") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "rvim") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 's':
        if (strcmp(fi->name, "socat") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 't':
        if (strcmp(fi->name, "telnet") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "tclsh") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'v':
        if (strcmp(fi->name, "vim") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "vi") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'w':
        if (strcmp(fi->name, "wish") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'l':
        if (strcmp(fi->name, "lua") == 0)
        {
            report_reverse_shell(fi, ar, cmdline);
            break;
        }
    }
}

/**
 * Checks to see if the current file name matches a file from the list of known breakouts
 * It can bind a shell to a local port to allow remote network access.
 * @param fi This is current file that we are inspecting
 * @param ar This is a structure containing all of enumy's findings
 * @param cmdline This is the runtime commandline arguments 
 */
void check_bind_shell(File_Info *fi, All_Results *ar, Args *cmdline)
{
    switch (fi->name[0])
    {
    case 'n':
        if (strcmp(fi->name, "nc") == 0)
        {
            report_bind_shell(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "netcat") == 0)
        {
            report_bind_shell(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "node") == 0)
        {
            report_bind_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 's':
        if (strcmp(fi->name, "socat") == 0)
        {
            report_bind_shell(fi, ar, cmdline);
            break;
        }
    }
}

/**
 * Checks to see if the current file name matches a file from the list of known breakouts
 * It can send back a non-interactive reverse shell to a listening attacker to open a remote network access.
 * @param fi This is current file that we are inspecting
 * @param ar This is a structure containing all of enumy's findings
 * @param cmdline This is the runtime commandline arguments 
 */
void check_non_interactive_bind_shell(File_Info *fi, All_Results *ar, Args *cmdline)
{
    switch (fi->name[0])
    {
    case 'a':
        if (strcmp(fi->name, "awk") == 0)
        {
            report_non_interactive_bind_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'g':
        if (strcmp(fi->name, "gawk") == 0)
        {
            report_non_interactive_bind_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'l':
        if (strcmp(fi->name, "lua") == 0)
        {
            report_non_interactive_bind_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'n':
        if (strcmp(fi->name, "nawk") == 0)
        {
            report_non_interactive_bind_shell(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "nmap") == 0)
        {
            report_non_interactive_bind_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'r':
        if (strcmp(fi->name, "rvim") == 0)
        {
            report_non_interactive_bind_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 't':
        if (strcmp(fi->name, "tclsh") == 0)
        {
            report_non_interactive_bind_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'v':
        if (strcmp(fi->name, "vim") == 0)
        {
            report_non_interactive_bind_shell(fi, ar, cmdline);
            break;
        }
        break;
    case 'w':
        if (strcmp(fi->name, "wish") == 0)
        {
            report_non_interactive_bind_shell(fi, ar, cmdline);
            break;
        }
        break;
    }
}

/**
 * Checks to see if the current file name matches a file from the list of known breakouts
 * It can exfiltrate files of the networking 
 * @param fi This is current file that we are inspecting
 * @param ar This is a structure containing all of enumy's findings
 * @param cmdline This is the runtime commandline arguments 
 */
void check_file_upload(File_Info *fi, All_Results *ar, Args *cmdline)
{
    switch (fi->name[0])
    {
    case 'b':
        if (strcmp(fi->name, "bash") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "busybox") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        break;
    case 'c':
        if (strcmp(fi->name, "cancel") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "cpan") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "curl") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        break;
    case 'e':
        if (strcmp(fi->name, "easy_install") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        break;
    case 'f':
        if (strcmp(fi->name, "finger") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "ftp") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        break;
    case 'g':
        if (strcmp(fi->name, "gdb") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "gimp") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        break;
    case 'i':
        if (strcmp(fi->name, "irb") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        break;
    case 'k':
        if (strcmp(fi->name, "ksh") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        break;
    case 'l':
        if (strcmp(fi->name, "lua") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        break;
    case 'n':
        if (strcmp(fi->name, "nc") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "nmap") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        break;
    case 'o':
        if (strcmp(fi->name, "openssl") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        break;
    case 'p':
        if (strcmp(fi->name, "php") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "pip") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "python") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        break;
    case 'r':
        if (strcmp(fi->name, "restic") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "rlogin") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "ruby") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "rvim") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        break;
    case 's':
        if (strcmp(fi->name, "scp") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "sftp") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "smbclient") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "socat") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "ssh") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        break;
    case 't':
        if (strcmp(fi->name, "tar") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "tftp") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        break;
    case 'v':
        if (strcmp(fi->name, "vim") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        break;
    case 'w':
        if (strcmp(fi->name, "wget") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "whois") == 0)
        {
            report_file_upload(fi, ar, cmdline);
            break;
        }
        break;
    }
}

/**
 * Checks to see if the current file name matches a file from the list of known breakouts
 * It can download remote files 
 * @param fi This is current file that we are inspecting
 * @param ar This is a structure containing all of enumy's findings
 * @param cmdline This is the runtime commandline arguments 
 */
void check_file_download(File_Info *fi, All_Results *ar, Args *cmdline)
{
    switch (fi->name[0])
    {
    case 'b':
        if (strcmp(fi->name, "bash") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        break;
    case 'c':
        if (strcmp(fi->name, "cpan") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "curl") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        break;
    case 'e':
        if (strcmp(fi->name, "easy_install") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        break;
    case 'f':
        if (strcmp(fi->name, "finger") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "ftp") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        break;
    case 'g':
        if (strcmp(fi->name, "gdb") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "gimp irb") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        break;
    case 'j':
        if (strcmp(fi->name, "jjs") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "jrunscript") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        break;
    case 'k':
        if (strcmp(fi->name, "ksh") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        break;
    case 'l':
        if (strcmp(fi->name, "lua") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "lwp-download") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        break;
    case 'n':
        if (strcmp(fi->name, "nc") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "nmap") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        break;
    case 'o':
        if (strcmp(fi->name, "openssl") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        break;
    case 'p':
        if (strcmp(fi->name, "php") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "pip") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "python") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        break;
    case 'r':
        if (strcmp(fi->name, "ruby") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "rvim") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        break;
    case 's':
        if (strcmp(fi->name, "scp") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "sftp") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "smblient") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "socat") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "ssh") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        break;
    case 't':
        if (strcmp(fi->name, "tar") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "tftp") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        break;
    case 'v':
        if (strcmp(fi->name, "vim") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        break;
    case 'w':
        if (strcmp(fi->name, "wget") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "whois") == 0)
        {
            report_file_download(fi, ar, cmdline);
            break;
        }
    }
}

/**
 * Checks to see if the current file name matches a file from the list of known breakouts
 * It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.
 * @param fi This is current file that we are inspecting
 * @param ar This is a structure containing all of enumy's findings
 * @param cmdline This is the runtime commandline arguments 
 */
void check_file_write(File_Info *fi, All_Results *ar, Args *cmdline)
{
    if (!has_suid(fi))
    {
        return;
    }
    switch (fi->name[0])
    {
    case 'a':
        if (strcmp(fi->name, "ash") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "awk") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        break;
    case 'b':
        if (strcmp(fi->name, "bash") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "busybox") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        break;
    case 'c':
        if (strcmp(fi->name, "cp") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "csh") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        break;
    case 'd':
        if (strcmp(fi->name, "dash") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "dd") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "docker") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        break;
    case 'e':
        if (strcmp(fi->name, "easy_install") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "ed") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "emacs") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        break;
    case 'g':
        if (strcmp(fi->name, "gawks") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "gdb") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "gimp") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        break;
    case 'i':
        if (strcmp(fi->name, "iconv") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "irb") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        break;
    case 'j':
        if (strcmp(fi->name, "jjs") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "jrunscript") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        break;
    case 'k':
        if (strcmp(fi->name, "ksh") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        break;
    case 'l':
        if (strcmp(fi->name, "less") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "lua") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        break;
    case 'm':
        if (strcmp(fi->name, "make") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "mawk") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        break;
    case 'n':
        if (strcmp(fi->name, "nano") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "nawk") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "nmap") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        break;
    case 'o':
        if (strcmp(fi->name, "openssl") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        break;
    case 'p':
        if (strcmp(fi->name, "pico") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "pip") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "puppet") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "python") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        break;
    case 'r':
        if (strcmp(fi->name, "red") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "rlwrap") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "ruby") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "run-mailcap") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "rvim") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        break;
    case 's':
        if (strcmp(fi->name, "screen") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "script") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "seed") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "shuf") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "sqlite3") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        break;
    case 't':
        if (strcmp(fi->name, "tar") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "tee") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        break;
    case 'v':
        if (strcmp(fi->name, "vi") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "vim") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
        break;
    case 'x':
        if (strcmp(fi->name, "xxd") == 0)
        {
            report_file_write(fi, ar, cmdline);
            break;
        }
    }
}

/**
 * Checks to see if the current file name matches a file from the list of known breakouts
 * It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.
 * @param fi This is current file that we are inspecting
 * @param ar This is a structure containing all of enumy's findings
 * @param cmdline This is the runtime commandline arguments 
 */
void check_file_read(File_Info *fi, All_Results *ar, Args *cmdline)
{
    if (!has_suid(fi))
    {
        return;
    }
    switch (fi->name[0])
    {
    case 'a':
        if (strcmp(fi->name, "arp") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "awk") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'b':
        if (strcmp(fi->name, "base32") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "base64") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "bash") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "busybox") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'c':
        if (strcmp(fi->name, "cat") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "cp") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "curl") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "cut") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'd':
        if (strcmp(fi->name, "date") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "dd") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "dialog") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "diff") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "dmesg") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "docker") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'e':
        if (strcmp(fi->name, "easy_install") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "ed") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "emacs") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "eqn") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "expand") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'f':
        if (strcmp(fi->name, "file") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "fmt") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "fold") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'g':
        if (strcmp(fi->name, "gawk") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "gdb") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "genisoimage") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "gimp") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "grep") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'h':
        if (strcmp(fi->name, "hd") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "head") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "hexdump") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "highlight") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'i':
        if (strcmp(fi->name, "iconv") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "ip") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "irb") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'j':
        if (strcmp(fi->name, "jjs") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "jq") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "jrunscript") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'k':
        if (strcmp(fi->name, "ksh") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "ksshell") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'l':
        if (strcmp(fi->name, "less") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "look") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "lua") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "lwp-request") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'm':
        if (strcmp(fi->name, "man") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "mawk") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "more") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "mtr") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'n':
        if (strcmp(fi->name, "nano") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "nawk") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "nl") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "nmap") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'o':
        if (strcmp(fi->name, "od") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "openssl") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'p':
        if (strcmp(fi->name, "pg") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "pico") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "pip") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "puppet") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "python") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "readelf") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'r':
        if (strcmp(fi->name, "red") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "redcarpet") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "ruby") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "run-mailcap") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "rvim") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 's':
        if (strcmp(fi->name, "sed") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "shuf") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "soelim") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "sort") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "sqlite3") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "ssh") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "strings") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 't':
        if (strcmp(fi->name, "tac") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "tail") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "tar") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'u':
        if (strcmp(fi->name, "ul") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "unexpand") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "uniq") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "uudecode") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "uuencode") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'v':
        if (strcmp(fi->name, "vi") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "vim") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'x':
        if (strcmp(fi->name, "xargs") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "xxd") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'y':
        if (strcmp(fi->name, "yelp") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    case 'z':
        if (strcmp(fi->name, "zsoelim") == 0)
        {
            report_file_read(fi, ar, cmdline);
            break;
        }
        break;
    }
}

/**
 * Checks to see if the current file name matches a file from the list of known breakouts
 * It loads shared libraries that may be used to run code in the binary execution context.
 * @param fi This is current file that we are inspecting
 * @param ar This is a structure containing all of enumy's findings
 * @param cmdline This is the runtime commandline arguments 
 */
void check_lib_load(File_Info *fi, All_Results *ar, Args *cmdline)
{
    if (!has_suid(fi))
    {
        return;
    }
    switch (fi->name[0])
    {
    case 'b':
        if (strcmp(fi->name, "bash") == 0)
        {
            report_lib_load(fi, ar, cmdline);
            break;
        }
        break;
    case 'e':
        if (strcmp(fi->name, "easy_install") == 0)
        {
            report_lib_load(fi, ar, cmdline);
            break;
        }
        break;
    case 'g':
        if (strcmp(fi->name, "gdb") == 0)
        {
            report_lib_load(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "gimp") == 0)
        {
            report_lib_load(fi, ar, cmdline);
            break;
        }
        break;
    case 'i':
        if (strcmp(fi->name, "irb") == 0)
        {
            report_lib_load(fi, ar, cmdline);
            break;
        }
        break;
    case 'm':
        if (strcmp(fi->name, "mysql") == 0)
        {
            report_lib_load(fi, ar, cmdline);
            break;
        }
        break;
    case 'o':
        if (strcmp(fi->name, "openssl") == 0)
        {
            report_lib_load(fi, ar, cmdline);
            break;
        }
        break;
    case 'p':
        if (strcmp(fi->name, "pip") == 0)
        {
            report_lib_load(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "python") == 0)
        {
            report_lib_load(fi, ar, cmdline);
            break;
        }
        break;
    case 'r':
        if (strcmp(fi->name, "ruby") == 0)
        {
            report_lib_load(fi, ar, cmdline);
            break;
        }
        if (strcmp(fi->name, "rvim") == 0)
        {
            report_lib_load(fi, ar, cmdline);
            break;
        }
        break;
    case 'v':
        if (strcmp(fi->name, "vim") == 0)
        {
            report_lib_load(fi, ar, cmdline);
            break;
        }
        break;
    }
}

void report_buildtools(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 255;
    char *name = "Development tool found";

    if (has_elf_magic_bytes(fi) == 0)
    {
        return;
    }

    Result *new_result = create_new_issue();
    set_id_and_desc(id, new_result);
    set_issue_location(fi->location, new_result);
    set_issue_name(name, new_result);
    add_new_result_medium(new_result, ar, cmdline);
}

void report_shell(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 256;
    char *name = "Executable that can breakout of restricted shell found";

    if (has_elf_magic_bytes(fi) == 0)
    {
        return;
    }

    Result *new_result = create_new_issue();
    set_id_and_desc(id, new_result);
    set_issue_location(fi->location, new_result);
    set_issue_name(name, new_result);
    add_new_result_low(new_result, ar, cmdline);
}

void report_reverse_shell(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 257;
    char *name = "Executable capable of spawning reverse shells found";

    if (has_elf_magic_bytes(fi) == 0)
    {
        return;
    }

    Result *new_result = create_new_issue();
    set_id_and_desc(id, new_result);
    set_issue_location(fi->location, new_result);
    set_issue_name(name, new_result);
    add_new_result_medium(new_result, ar, cmdline);
}

void report_bind_shell(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 258;
    char *name = "Executable capable of spawning bind shells found";

    if (has_elf_magic_bytes(fi) == 0)
    {
        return;
    }

    Result *new_result = create_new_issue();
    set_id_and_desc(id, new_result);
    set_issue_location(fi->location, new_result);
    set_issue_name(name, new_result);
    add_new_result_medium(new_result, ar, cmdline);
}

void report_non_interactive_bind_shell(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 259;
    char *name = "Executable capable of spawning non interactive bind shells found";

    if (has_elf_magic_bytes(fi) == 0)
    {
        return;
    }

    Result *new_result = create_new_issue();
    set_id_and_desc(id, new_result);
    set_issue_location(fi->location, new_result);
    set_issue_name(name, new_result);
    add_new_result_medium(new_result, ar, cmdline);
}

void report_file_upload(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 260;
    char *name = "Executable capable of exfiltrating files off the network found";

    if (has_elf_magic_bytes(fi) == 0)
    {
        return;
    }

    Result *new_result = create_new_issue();
    set_id_and_desc(id, new_result);
    set_issue_location(fi->location, new_result);
    set_issue_name(name, new_result);
    add_new_result_low(new_result, ar, cmdline);
}

void report_file_read(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 261;
    char *name = "Executable capable of reading arbitrary files as root";

    if (has_elf_magic_bytes(fi) == 0)
    {
        return;
    }

    Result *new_result = create_new_issue();
    set_id_and_desc(id, new_result);
    set_issue_location(fi->location, new_result);
    set_issue_name(name, new_result);
    add_new_result_high(new_result, ar, cmdline);
}

void report_file_write(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 262;
    char *name = "Executable capable of writing arbitrary files as root";

    if (has_elf_magic_bytes(fi) == 0)
    {
        return;
    }

    Result *new_result = create_new_issue();
    set_id_and_desc(id, new_result);
    set_issue_location(fi->location, new_result);
    set_issue_name(name, new_result);
    add_new_result_high(new_result, ar, cmdline);
}

void report_lib_load(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 263;
    char *name = "Executable capable of loading shared libaries as root";

    if (has_elf_magic_bytes(fi) == 0)
    {
        return;
    }

    Result *new_result = create_new_issue();
    set_id_and_desc(id, new_result);
    set_issue_location(fi->location, new_result);
    set_issue_name(name, new_result);
    add_new_result_high(new_result, ar, cmdline);
}

void report_file_download(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 264;
    char *name = "Executable capable of downloading files";

    if (has_elf_magic_bytes(fi) == 0)
    {
        return;
    }

    Result *new_result = create_new_issue();
    set_id_and_desc(id, new_result);
    set_issue_location(fi->location, new_result);
    set_issue_name(name, new_result);
    add_new_result_low(new_result, ar, cmdline);
}