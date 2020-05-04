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

int break_out_binary_scan(File_Info *fi, All_Results *ar, Args *cmdline);
static void add_issue(int id, char *name, File_Info *fi, All_Results *ar, Args *cmdline);

/**
 * Should only be called if the file is known to be SUID or GUID or can be run as root e.g $sudo -l 
 * Compares the current file and tests to see if it matches a list of known breakout binaries
 * @param fi current files information 
 * @param ar struct containing all of the results enumy has foundd
 * @param cmdline list of cmdline arguments 
 */
int break_out_binary_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id;
    switch (fi->name[0])
    {
    case 'a':
        if (strcmp(fi->name, "apt-get") == 0)
        {
            id = 49;
            add_issue(id, "apt-get", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "apt") == 0)
        {
            id = 50;
            add_issue(id, "apt", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "aria2c") == 0)
        {
            id = 51;
            add_issue(id, "aria2c", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "arp") == 0)
        {
            id = 52;
            add_issue(id, "arp", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "ash") == 0)
        {
            id = 53;
            add_issue(id, "ash", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "awk") == 0)
        {
            id = 54;
            add_issue(id, "awk", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'b':
        if (strcmp(fi->name, "base32") == 0)
        {
            id = 55;
            add_issue(id, "base32", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "base64") == 0)
        {
            id = 56;
            add_issue(id, "base64", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "bash") == 0)
        {
            id = 57;
            add_issue(id, "bash", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "bpftrace") == 0)
        {
            id = 58;
            add_issue(id, "bpftrace", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "bundler") == 0)
        {
            id = 59;
            add_issue(id, "bundler", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "busctl") == 0)
        {
            id = 60;
            add_issue(id, "busctl", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "busybox") == 0)
        {
            id = 61;
            add_issue(id, "busybox", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "byebug") == 0)
        {
            id = 62;
            add_issue(id, "byebug", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'c':
        if (strcmp(fi->name, "cancel") == 0)
        {
            id = 63;
            add_issue(id, "cancel", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "cat") == 0)
        {
            id = 64;
            add_issue(id, "cat", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "chmod") == 0)
        {
            id = 65;
            add_issue(id, "chmod", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "chown") == 0)
        {
            id = 66;
            add_issue(id, "chown", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "chroot") == 0)
        {
            id = 67;
            add_issue(id, "chroot", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "cobc") == 0)
        {
            id = 68;
            add_issue(id, "cobc", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "cp") == 0)
        {
            id = 69;
            add_issue(id, "cp", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "cpan") == 0)
        {
            id = 70;
            add_issue(id, "cpan", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "cpulimit") == 0)
        {
            id = 71;
            add_issue(id, "cpulimit", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "crash") == 0)
        {
            id = 72;
            add_issue(id, "crash", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "crontab") == -0)
        {
            id = 73;
            add_issue(id, "crontab", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "csh") == 0)
        {
            id = 74;
            add_issue(id, "csh", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "curl") == 0)
        {
            id = 75;
            add_issue(id, "curl", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "cut") == 0)
        {
            id = 76;
            add_issue(id, "cut", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'd':
        if (strcmp(fi->name, "dash") == 0)
        {
            id = 77;
            add_issue(id, "dash", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "date") == 0)
        {
            id = 78;
            add_issue(id, "date", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "dmidecode") == 0)
        {
            id = 234;
            add_issue(id, "dmidecode", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "dd") == 0)
        {
            id = 79;
            add_issue(id, "dd", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "dialog") == 0)
        {
            id = 80;
            add_issue(id, "dialog", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "diff") == 0)
        {
            id = 81;
            add_issue(id, "diff", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "dmesg") == 0)
        {
            id = 82;
            add_issue(id, "dmesg", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "dmsetup") == 0)
        {
            id = 83;
            add_issue(id, "dmsetup", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "dnf") == 0)
        {
            id = 84;
            add_issue(id, "dnf", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "docker") == 0)
        {
            id = 85;
            add_issue(id, "docker", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "dpkg") == 0)
        {
            id = 86;
            add_issue(id, "dpkg", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'e':
        if (strcmp(fi->name, "easy_install") == 0)
        {
            id = 87;
            add_issue(id, "easy_install", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "eb") == 0)
        {
            id = 88;
            add_issue(id, "eb", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "ed") == 0)
        {
            id = 89;
            add_issue(id, "ed", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "emacs") == 0)
        {
            id = 90;
            add_issue(id, "emacs", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "env") == 0)
        {
            id = 91;
            add_issue(id, "env", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "eqn") == 0)
        {
            id = 92;
            add_issue(id, "eqn", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "expand") == 0)
        {
            id = 93;
            add_issue(id, "expand", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "expect") == 0)
        {
            id = 94;
            add_issue(id, "expect", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'f':
        if (strcmp(fi->name, "facter") == 0)
        {
            id = 95;
            add_issue(id, "facter", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "file") == 0)
        {
            id = 96;
            add_issue(id, "file", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "find") == 0)
        {
            id = 97;
            add_issue(id, "find", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "finger") == 0)
        {
            id = 98;
            add_issue(id, "finger", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "flock") == 0)
        {
            id = 99;
            add_issue(id, "flock", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "fmt") == 0)
        {
            id = 100;
            add_issue(id, "fmt", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "fold") == 0)
        {
            id = 101;
            add_issue(id, "fold", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "ftp") == 0)
        {
            id = 102;
            add_issue(id, "ftp", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'g':
        if (strcmp(fi->name, "gawk") == 0)
        {
            id = 103;
            add_issue(id, "gawk", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "gcc") == 0)
        {
            id = 104;
            add_issue(id, "gcc", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "gdb") == 0)
        {
            id = 105;
            add_issue(id, "gdb", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "gem") == 0)
        {
            id = 106;
            add_issue(id, "gem", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "genisoimage") == 0)
        {
            id = 107;
            add_issue(id, "genisoimage", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "gimp") == 0)
        {
            id = 108;
            add_issue(id, "gimp", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "git") == 0)
        {
            id = 109;
            add_issue(id, "git", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "grep") == 0)
        {
            id = 110;
            add_issue(id, "grep", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "gtester") == 0)
        {
            id = 111;
            add_issue(id, "gtester", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'h':
        if (strcmp(fi->name, "hd") == 0)
        {
            id = 112;
            add_issue(id, "hd", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "head") == 0)
        {
            id = 113;
            add_issue(id, "head", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "hexdump") == 0)
        {
            id = 114;
            add_issue(id, "hexdump", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "highlight") == 0)
        {
            id = 115;
            add_issue(id, "highlight", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'i':
        if (strcmp(fi->name, "iconv") == 0)
        {
            id = 116;
            add_issue(id, "iconv", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "iftop") == 0)
        {
            id = 117;
            add_issue(id, "iftop", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "ionice") == 0)
        {
            id = 118;
            add_issue(id, "ionice", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "ip") == 0)
        {
            id = 119;
            add_issue(id, "ip", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "irb") == 0)
        {
            id = 120;
            add_issue(id, "irb", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'j':
        if (strcmp(fi->name, "jjs") == 0)
        {
            id = 121;
            add_issue(id, "jjs", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "journalctl") == 0)
        {
            id = 122;
            add_issue(id, "journalctl", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "jq") == 0)
        {
            id = 123;
            add_issue(id, "jq", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "jrunscript") == 0)
        {
            id = 124;
            add_issue(id, "jrunscript", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'k':
        if (strcmp(fi->name, "ksh") == 0)
        {
            id = 126;
            add_issue(id, "ksh", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "kshksshell") == 0)
        {
            id = 125;
            add_issue(id, "kshksshell", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'l':
        if (strcmp(fi->name, "ld.so") == 0)
        {
            id = 127;
            add_issue(id, "ld", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "ldconfig") == 0)
        {
            id = 128;
            add_issue(id, "ldconfig", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "less") == 0)
        {
            id = 129;
            add_issue(id, "less", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "logsave") == 0)
        {
            id = 130;
            add_issue(id, "logsave", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "look") == 0)
        {
            id = 131;
            add_issue(id, "look", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "ltrace") == 0)
        {
            id = 132;
            add_issue(id, "ltrace", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "lua") == 0)
        {
            id = 133;
            add_issue(id, "lua", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "lwp-download") == 0)
        {
            id = 134;
            add_issue(id, "lwp-download", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "lwp-request") == 0)
        {
            id = 135;
            add_issue(id, "lwp-request", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'm':
        if (strcmp(fi->name, "mail") == 0)
        {
            id = 136;
            add_issue(id, "mail", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "make") == 0)
        {
            id = 137;
            add_issue(id, "make", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "man") == 0)
        {
            id = 138;
            add_issue(id, "man", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "mawk") == 0)
        {
            id = 139;
            add_issue(id, "mawk", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "more") == 0)
        {
            id = 140;
            add_issue(id, "more", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "mount") == 0)
        {
            id = 141;
            add_issue(id, "mount", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "mtr") == 0)
        {
            id = 142;
            add_issue(id, "mtr", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "mv") == 0)
        {
            id = 143;
            add_issue(id, "mv", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "mysql") == 0)
        {
            id = 144;
            add_issue(id, "mysql", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'n':
        if (strcmp(fi->name, "nano") == 0)
        {
            id = 145;
            add_issue(id, "nano", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "nawk") == 0)
        {
            id = 146;
            add_issue(id, "nawk", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "nc") == 0)
        {
            id = 147;
            add_issue(id, "nc", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "nice") == 0)
        {
            id = 148;
            add_issue(id, "nice", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "nl") == 0)
        {
            id = 149;
            add_issue(id, "nl", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "nmap") == 0)
        {
            id = 150;
            add_issue(id, "nmap", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "node") == 0)
        {
            id = 151;
            add_issue(id, "node", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "nohup") == 0)
        {
            id = 152;
            add_issue(id, "nohup", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "nroff") == 0)
        {
            id = 153;
            add_issue(id, "nroff", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "nsenter") == 0)
        {
            id = 154;
            add_issue(id, "nsenter", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'o':
        if (strcmp(fi->name, "od") == 0)
        {
            id = 155;
            add_issue(id, "od", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "openssl") == 0)
        {
            id = 156;
            add_issue(id, "openssl", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'p':
        if (strcmp(fi->name, "pdb") == 0)
        {
            id = 157;
            add_issue(id, "pdb", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "perl") == 0)
        {
            id = 158;
            add_issue(id, "perl", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "pg") == 0)
        {
            id = 159;
            add_issue(id, "pg", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "php") == 0)
        {
            id = 160;
            add_issue(id, "php", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "pic") == 0)
        {
            id = 161;
            add_issue(id, "pic", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "pico") == 0)
        {
            id = 162;
            add_issue(id, "pico", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "pip") == 0)
        {
            id = 163;
            add_issue(id, "pip", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "pry") == 0)
        {
            id = 164;
            add_issue(id, "pry", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "puppet") == 0)
        {
            id = 165;
            add_issue(id, "puppet", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "python") == 0)
        {
            id = 166;
            add_issue(id, "python", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'r':
        if (strcmp(fi->name, "rake") == 0)
        {
            id = 167;
            add_issue(id, "rake", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "readelf") == 0)
        {
            id = 168;
            add_issue(id, "readelf", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "red") == 0)
        {
            id = 169;
            add_issue(id, "red", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "redcarpet") == 0)
        {
            id = 170;
            add_issue(id, "redcarpet", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "restic") == 0)
        {
            id = 171;
            add_issue(id, "restic", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "rlogin") == 0)
        {
            id = 172;
            add_issue(id, "rlogin", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "rlwrap") == 0)
        {
            id = 173;
            add_issue(id, "rlwrap", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "rpm") == 0)
        {
            id = 174;
            add_issue(id, "rpm", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "rpmquery") == 0)
        {
            id = 175;
            add_issue(id, "rpmquery", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "rsync") == 0)
        {
            id = 176;
            add_issue(id, "rsync", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "ruby") == 0)
        {
            id = 177;
            add_issue(id, "ruby", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "run-mailcap") == 0)
        {
            id = 178;
            add_issue(id, "run", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "run-parts") == 0)
        {
            id = 179;
            add_issue(id, "run-parts", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "rvim") == 0)
        {
            id = 180;
            add_issue(id, "rvim", fi, ar, cmdline);
            return 1;
        }
        break;
    case 's':
        if (strcmp(fi->name, "scp") == 0)
        {
            id = 181;
            add_issue(id, "scp", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "screen") == 0)
        {
            id = 182;
            add_issue(id, "screen", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "script") == 0)
        {
            id = 183;
            add_issue(id, "script", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "sed") == 0)
        {
            id = 184;
            add_issue(id, "sed", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "service") == 0)
        {
            id = 185;
            add_issue(id, "service", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "setarch") == 0)
        {
            id = 186;
            add_issue(id, "setarch", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "sftp") == 0)
        {
            id = 187;
            add_issue(id, "sftp", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "shuf") == 0)
        {
            id = 188;
            add_issue(id, "shuf", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "smbclient") == 0)
        {
            id = 189;
            add_issue(id, "smbclient", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "socat") == 0)
        {
            id = 190;
            add_issue(id, "socat", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "soelim") == 0)
        {
            id = 191;
            add_issue(id, "soelim", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "sort") == 0)
        {
            id = 192;
            add_issue(id, "sort", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "sqlite4") == 0)
        {
            id = 193;
            add_issue(id, "sqlite4", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "ssh") == 0)
        {
            id = 194;
            add_issue(id, "ssh", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "start-stop-daemon") == 0)
        {
            id = 195;
            add_issue(id, "start-stop-daemon", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "stdbuf") == 0)
        {
            id = 196;
            add_issue(id, "stdbuf", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "strace") == 0)
        {
            id = 197;
            add_issue(id, "strace", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "strings") == 0)
        {
            id = 198;
            add_issue(id, "strings", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "systemctl") == 0)
        {
            id = 199;
            add_issue(id, "systemctl", fi, ar, cmdline);
            return 1;
        }
        break;
    case 't':
        if (strcmp(fi->name, "tac") == 0)
        {
            id = 200;
            add_issue(id, "tac", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "tail") == 0)
        {
            id = 201;
            add_issue(id, "tail", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "tar") == 0)
        {
            id = 202;
            add_issue(id, "tar", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "taskset") == 0)
        {
            id = 203;
            add_issue(id, "taskset", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "tclsh") == 0)
        {
            id = 204;
            add_issue(id, "tclsh", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "tcpdump") == 0)
        {
            id = 205;
            add_issue(id, "tcpdump", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "tee") == 0)
        {
            id = 206;
            add_issue(id, "tee", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "telnet") == 0)
        {
            id = 207;
            add_issue(id, "telnet", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "tftp") == 0)
        {
            id = 208;
            add_issue(id, "tftp", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "time") == 0)
        {
            id = 209;
            add_issue(id, "time", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "timeout") == 0)
        {
            id = 210;
            add_issue(id, "timeout", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "tmux") == 0)
        {
            id = 211;
            add_issue(id, "tmux", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "top") == 0)
        {
            id = 212;
            add_issue(id, "top", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'u':
        if (strcmp(fi->name, "ul") == 0)
        {
            id = 213;
            add_issue(id, "ul", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "unexpand") == 0)
        {
            id = 214;
            add_issue(id, "unexpand", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "uniq") == 0)
        {
            id = 215;
            add_issue(id, "uniq", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "unshare") == 0)
        {
            id = 216;
            add_issue(id, "unshare", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "uudecode") == 0)
        {
            id = 217;
            add_issue(id, "uudecode", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "uuencode") == 0)
        {
            id = 218;
            add_issue(id, "uuencode", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'v':
        if (strcmp(fi->name, "valgrind") == 0)
        {
            id = 219;
            add_issue(id, "valgrind", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "vi") == 0)
        {
            id = 220;
            add_issue(id, "vi", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "vim") == 0)
        {
            id = 221;
            add_issue(id, "vim", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'w':
        if (strcmp(fi->name, "watch") == 0)
        {
            id = 222;
            add_issue(id, "watch", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "wget") == 0)
        {
            id = 223;
            add_issue(id, "wget", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "whois") == 0)
        {
            id = 224;
            add_issue(id, "whois", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "wish") == 0)
        {
            id = 225;
            add_issue(id, "wish", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'x':
        if (strcmp(fi->name, "xarg") == 0)
        {
            id = 226;
            add_issue(id, "xarg", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "xxd") == 0)
        {
            id = 227;
            add_issue(id, "xxd", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'y':
        if (strcmp(fi->name, "yelp") == 0)
        {
            id = 228;
            add_issue(id, "yelp", fi, ar, cmdline);
            return 1;
        }
        else if (strcmp(fi->name, "yum") == 0)
        {
            id = 229;
            add_issue(id, "yum", fi, ar, cmdline);
            return 1;
        }
        break;
    case 'z':
        if (strcmp(fi->name, "zip") == 0)
        {
            id = 230;
            add_issue(id, "zip", fi, ar, cmdline);
            return 1;
        }
        if (strcmp(fi->name, "zsh") == 0)
        {
            id = 231;
            add_issue(id, "zsh", fi, ar, cmdline);
            return 1;
        }
        if (strcmp(fi->name, "zsoelim") == 0)
        {
            id = 232;
            add_issue(id, "zsoelim", fi, ar, cmdline);
            return 1;
        }
        if (strcmp(fi->name, "zypper") == 0)
        {
            id = 233;
            add_issue(id, "zypper", fi, ar, cmdline);
            return 1;
        }
        break;
    }
    return 0;
}

/**
 * Adds a findings to the ar.
 * @param id issues new id 
 * @param name name of the breakout binary
 * @param fi file information for the file 
 * @param ar struct containing all the results that enumy has found on the system
 * @param cmdline a struct continaing the runtime arguments for enumy 
 */
static void add_issue(int id, char *name, File_Info *fi, All_Results *ar, Args *cmdline)
{
    char issue_name[MAXSIZE];
    char *base_name = " breakout binary found";

    strncpy(issue_name, name, MAXSIZE - strlen(base_name));
    strcat(issue_name, base_name);

    Result *new_result = create_new_issue();
    set_id_and_desc(id, new_result);
    set_issue_location(fi->location, new_result);
    set_issue_name(issue_name, new_result);
    add_new_result_high(new_result, ar, cmdline);
}