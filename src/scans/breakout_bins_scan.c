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
static bool compare_and_add_issue(int id, File_Info *fi, All_Results *ar, Args *cmdline, char *search_str);

/**
 * Should only be called if the file is known to be SUID or GUID or can be run as root e.g $sudo -l 
 * Compares the current file and tests to see if it matches a list of known breakout binaries
 * @param fi current files information 
 * @param ar struct containing all of the results enumy has foundd
 * @param cmdline list of cmdline arguments 
 */
int break_out_binary_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    switch (fi->name[0])
    {
    case 'a':
        if (
            compare_and_add_issue(49, fi, ar, cmdline, "apt-get") ||
            compare_and_add_issue(50, fi, ar, cmdline, "apt") ||
            compare_and_add_issue(51, fi, ar, cmdline, "aria2c") ||
            compare_and_add_issue(52, fi, ar, cmdline, "arp") ||
            compare_and_add_issue(53, fi, ar, cmdline, "ash") ||
            compare_and_add_issue(54, fi, ar, cmdline, "awk"))
            return 1;
        return 0;
    case 'b':
        if (
            compare_and_add_issue(55, fi, ar, cmdline, "base32") ||
            compare_and_add_issue(56, fi, ar, cmdline, "base64") ||
            compare_and_add_issue(57, fi, ar, cmdline, "bash") ||
            compare_and_add_issue(58, fi, ar, cmdline, "bpftrace") ||
            compare_and_add_issue(59, fi, ar, cmdline, "bundler") ||
            compare_and_add_issue(60, fi, ar, cmdline, "busctl") ||
            compare_and_add_issue(61, fi, ar, cmdline, "busybox") ||
            compare_and_add_issue(62, fi, ar, cmdline, "byebug"))
            return 1;
        return 0;
    case 'c':
        if (
            compare_and_add_issue(63, fi, ar, cmdline, "cancel") ||
            compare_and_add_issue(64, fi, ar, cmdline, "cat") ||
            compare_and_add_issue(65, fi, ar, cmdline, "chmod") ||
            compare_and_add_issue(66, fi, ar, cmdline, "chown") ||
            compare_and_add_issue(67, fi, ar, cmdline, "chroot") ||
            compare_and_add_issue(68, fi, ar, cmdline, "cobc") ||
            compare_and_add_issue(69, fi, ar, cmdline, "cp") ||
            compare_and_add_issue(70, fi, ar, cmdline, "cpan") ||
            compare_and_add_issue(71, fi, ar, cmdline, "cpulimit") ||
            compare_and_add_issue(72, fi, ar, cmdline, "crash") ||
            compare_and_add_issue(73, fi, ar, cmdline, "crontab") ||
            compare_and_add_issue(74, fi, ar, cmdline, "csh") ||
            compare_and_add_issue(75, fi, ar, cmdline, "curl") ||
            compare_and_add_issue(76, fi, ar, cmdline, "cut"))
            return 1;
        return 0;
    case 'd':
        if (
            compare_and_add_issue(77, fi, ar, cmdline, "dash") ||
            compare_and_add_issue(78, fi, ar, cmdline, "date") ||
            compare_and_add_issue(79, fi, ar, cmdline, "dmidecode") ||
            compare_and_add_issue(80, fi, ar, cmdline, "dd") ||
            compare_and_add_issue(81, fi, ar, cmdline, "dialog") ||
            compare_and_add_issue(82, fi, ar, cmdline, "diff") ||
            compare_and_add_issue(83, fi, ar, cmdline, "dmesg") ||
            compare_and_add_issue(84, fi, ar, cmdline, "dmsetup") ||
            compare_and_add_issue(85, fi, ar, cmdline, "dnf") ||
            compare_and_add_issue(86, fi, ar, cmdline, "docker"))
            return 1;
        return 0;
    case 'e':
        if (
            compare_and_add_issue(87, fi, ar, cmdline, "easy_install") ||
            compare_and_add_issue(88, fi, ar, cmdline, "eb") ||
            compare_and_add_issue(89, fi, ar, cmdline, "ed") ||
            compare_and_add_issue(90, fi, ar, cmdline, "emacs") ||
            compare_and_add_issue(91, fi, ar, cmdline, "env") ||
            compare_and_add_issue(92, fi, ar, cmdline, "eqn") ||
            compare_and_add_issue(93, fi, ar, cmdline, "expand") ||
            compare_and_add_issue(94, fi, ar, cmdline, "expect"))
            return 1;
        return 0;
    case 'f':
        if (
            compare_and_add_issue(95, fi, ar, cmdline, "facter") ||
            compare_and_add_issue(96, fi, ar, cmdline, "file") ||
            compare_and_add_issue(97, fi, ar, cmdline, "find") ||
            compare_and_add_issue(98, fi, ar, cmdline, "finger") ||
            compare_and_add_issue(99, fi, ar, cmdline, "flock") ||
            compare_and_add_issue(100, fi, ar, cmdline, "fmt") ||
            compare_and_add_issue(101, fi, ar, cmdline, "fold") ||
            compare_and_add_issue(102, fi, ar, cmdline, "ftp"))
            return 1;
        return 0;
    case 'g':
        if (
            compare_and_add_issue(103, fi, ar, cmdline, "gawk") ||
            compare_and_add_issue(104, fi, ar, cmdline, "gcc") ||
            compare_and_add_issue(105, fi, ar, cmdline, "gdb") ||
            compare_and_add_issue(106, fi, ar, cmdline, "gem") ||
            compare_and_add_issue(107, fi, ar, cmdline, "genisoimage") ||
            compare_and_add_issue(108, fi, ar, cmdline, "gimp") ||
            compare_and_add_issue(109, fi, ar, cmdline, "git") ||
            compare_and_add_issue(110, fi, ar, cmdline, "grep") ||
            compare_and_add_issue(111, fi, ar, cmdline, "gtester"))
            return 1;
        return 0;
    case 'h':
        if (
            compare_and_add_issue(112, fi, ar, cmdline, "hd") ||
            compare_and_add_issue(113, fi, ar, cmdline, "head") ||
            compare_and_add_issue(114, fi, ar, cmdline, "hexdump") ||
            compare_and_add_issue(115, fi, ar, cmdline, "highlight"))
            return 1;
        return 0;
    case 'i':
        if (
            compare_and_add_issue(116, fi, ar, cmdline, "iconv") ||
            compare_and_add_issue(117, fi, ar, cmdline, "iftop") ||
            compare_and_add_issue(118, fi, ar, cmdline, "ionice") ||
            compare_and_add_issue(119, fi, ar, cmdline, "ip") ||
            compare_and_add_issue(120, fi, ar, cmdline, "irb"))
            return 1;
        return 0;
    case 'j':
        if (
            compare_and_add_issue(121, fi, ar, cmdline, "jjs") ||
            compare_and_add_issue(122, fi, ar, cmdline, "journalctl") ||
            compare_and_add_issue(123, fi, ar, cmdline, "jq") ||
            compare_and_add_issue(124, fi, ar, cmdline, "jrunscript"))
            return 1;
        return 0;
    case 'k':
        if (
            compare_and_add_issue(125, fi, ar, cmdline, "ksh") ||
            compare_and_add_issue(126, fi, ar, cmdline, "kshell"))
            return 1;
        return 0;
    case 'l':
        if (
            compare_and_add_issue(127, fi, ar, cmdline, "ld.so") ||
            compare_and_add_issue(128, fi, ar, cmdline, "ldconfig") ||
            compare_and_add_issue(129, fi, ar, cmdline, "less") ||
            compare_and_add_issue(130, fi, ar, cmdline, "logsave") ||
            compare_and_add_issue(131, fi, ar, cmdline, "look") ||
            compare_and_add_issue(132, fi, ar, cmdline, "ltrace") ||
            compare_and_add_issue(133, fi, ar, cmdline, "lua") ||
            compare_and_add_issue(134, fi, ar, cmdline, "lwp-download") ||
            compare_and_add_issue(135, fi, ar, cmdline, "lwp-request"))
            return 1;
        return 0;
    case 'm':
        if (
            compare_and_add_issue(136, fi, ar, cmdline, "mail") ||
            compare_and_add_issue(137, fi, ar, cmdline, "make") ||
            compare_and_add_issue(138, fi, ar, cmdline, "man") ||
            compare_and_add_issue(139, fi, ar, cmdline, "mawk") ||
            compare_and_add_issue(140, fi, ar, cmdline, "more") ||
            compare_and_add_issue(141, fi, ar, cmdline, "mount") ||
            compare_and_add_issue(142, fi, ar, cmdline, "mtr") ||
            compare_and_add_issue(143, fi, ar, cmdline, "mv") ||
            compare_and_add_issue(144, fi, ar, cmdline, "mysql"))
            return 1;
        return 0;
    case 'n':
        if (
            compare_and_add_issue(145, fi, ar, cmdline, "nano") ||
            compare_and_add_issue(146, fi, ar, cmdline, "nawk") ||
            compare_and_add_issue(147, fi, ar, cmdline, "nc") ||
            compare_and_add_issue(148, fi, ar, cmdline, "nice") ||
            compare_and_add_issue(149, fi, ar, cmdline, "nl") ||
            compare_and_add_issue(150, fi, ar, cmdline, "nmap") ||
            compare_and_add_issue(151, fi, ar, cmdline, "node") ||
            compare_and_add_issue(152, fi, ar, cmdline, "nohup") ||
            compare_and_add_issue(153, fi, ar, cmdline, "nroff") ||
            compare_and_add_issue(154, fi, ar, cmdline, "nsenter"))
            return 1;
        return 0;
    case 'o':
        if (
            compare_and_add_issue(155, fi, ar, cmdline, "od") ||
            compare_and_add_issue(156, fi, ar, cmdline, "openssl"))
            return 1;
        return 0;
    case 'p':
        if (
            compare_and_add_issue(157, fi, ar, cmdline, "pdb") ||
            compare_and_add_issue(158, fi, ar, cmdline, "perl") ||
            compare_and_add_issue(159, fi, ar, cmdline, "pg") ||
            compare_and_add_issue(160, fi, ar, cmdline, "php") ||
            compare_and_add_issue(161, fi, ar, cmdline, "pic") ||
            compare_and_add_issue(162, fi, ar, cmdline, "pico") ||
            compare_and_add_issue(163, fi, ar, cmdline, "pip") ||
            compare_and_add_issue(164, fi, ar, cmdline, "pry") ||
            compare_and_add_issue(165, fi, ar, cmdline, "puppet") ||
            compare_and_add_issue(166, fi, ar, cmdline, "python"))
            return 1;
        return 0;
    case 'r':
        if (
            compare_and_add_issue(167, fi, ar, cmdline, "rake") ||
            compare_and_add_issue(168, fi, ar, cmdline, "readelf") ||
            compare_and_add_issue(169, fi, ar, cmdline, "red") ||
            compare_and_add_issue(170, fi, ar, cmdline, "redcarpet") ||
            compare_and_add_issue(171, fi, ar, cmdline, "restic") ||
            compare_and_add_issue(172, fi, ar, cmdline, "rlogin") ||
            compare_and_add_issue(173, fi, ar, cmdline, "rlwrap") ||
            compare_and_add_issue(174, fi, ar, cmdline, "rpm") ||
            compare_and_add_issue(175, fi, ar, cmdline, "rpmquery") ||
            compare_and_add_issue(176, fi, ar, cmdline, "rsync") ||
            compare_and_add_issue(177, fi, ar, cmdline, "ruby") ||
            compare_and_add_issue(178, fi, ar, cmdline, "run-mailcap") ||
            compare_and_add_issue(179, fi, ar, cmdline, "run-parts") ||
            compare_and_add_issue(180, fi, ar, cmdline, "rvim"))
            return 1;
        return 0;
    case 's':
        if (
            compare_and_add_issue(181, fi, ar, cmdline, "scp") ||
            compare_and_add_issue(182, fi, ar, cmdline, "screen") ||
            compare_and_add_issue(183, fi, ar, cmdline, "script") ||
            compare_and_add_issue(184, fi, ar, cmdline, "sed") ||
            compare_and_add_issue(185, fi, ar, cmdline, "service") ||
            compare_and_add_issue(186, fi, ar, cmdline, "setarch") ||
            compare_and_add_issue(187, fi, ar, cmdline, "sftp") ||
            compare_and_add_issue(188, fi, ar, cmdline, "shuf") ||
            compare_and_add_issue(189, fi, ar, cmdline, "smbclient") ||
            compare_and_add_issue(190, fi, ar, cmdline, "socat") ||
            compare_and_add_issue(191, fi, ar, cmdline, "soelim") ||
            compare_and_add_issue(192, fi, ar, cmdline, "sort") ||
            compare_and_add_issue(193, fi, ar, cmdline, "sqlite4") ||
            compare_and_add_issue(194, fi, ar, cmdline, "ssh") ||
            compare_and_add_issue(195, fi, ar, cmdline, "start-stop-daemon") ||
            compare_and_add_issue(196, fi, ar, cmdline, "stdbuff") ||
            compare_and_add_issue(197, fi, ar, cmdline, "strace") ||
            compare_and_add_issue(198, fi, ar, cmdline, "strings") ||
            compare_and_add_issue(199, fi, ar, cmdline, "systemctl"))
            return 1;
        return 0;
    case 't':
        if (
            compare_and_add_issue(200, fi, ar, cmdline, "tac") ||
            compare_and_add_issue(201, fi, ar, cmdline, "tail") ||
            compare_and_add_issue(202, fi, ar, cmdline, "tar") ||
            compare_and_add_issue(203, fi, ar, cmdline, "taskset") ||
            compare_and_add_issue(204, fi, ar, cmdline, "tclsh") ||
            compare_and_add_issue(205, fi, ar, cmdline, "tcpdump") ||
            compare_and_add_issue(206, fi, ar, cmdline, "tee") ||
            compare_and_add_issue(207, fi, ar, cmdline, "telnet") ||
            compare_and_add_issue(208, fi, ar, cmdline, "tftp") ||
            compare_and_add_issue(209, fi, ar, cmdline, "time") ||
            compare_and_add_issue(210, fi, ar, cmdline, "timeout") ||
            compare_and_add_issue(211, fi, ar, cmdline, "tmux") ||
            compare_and_add_issue(212, fi, ar, cmdline, "top"))
            return 1;
        return 0;
    case 'u':
        if (
            compare_and_add_issue(213, fi, ar, cmdline, "ul") ||
            compare_and_add_issue(214, fi, ar, cmdline, "unexpand") ||
            compare_and_add_issue(215, fi, ar, cmdline, "uniq") ||
            compare_and_add_issue(216, fi, ar, cmdline, "unshare") ||
            compare_and_add_issue(217, fi, ar, cmdline, "uudecode") ||
            compare_and_add_issue(218, fi, ar, cmdline, "uuencode"))
            return 1;
        return 0;
    case 'v':
        if (
            compare_and_add_issue(219, fi, ar, cmdline, "valgrind") ||
            compare_and_add_issue(220, fi, ar, cmdline, "vi") ||
            compare_and_add_issue(221, fi, ar, cmdline, "vim"))
            return 1;
        return 0;
    case 'w':
        if (
            compare_and_add_issue(222, fi, ar, cmdline, "watch") ||
            compare_and_add_issue(223, fi, ar, cmdline, "wget") ||
            compare_and_add_issue(224, fi, ar, cmdline, "whois") ||
            compare_and_add_issue(225, fi, ar, cmdline, "wish"))
            return 1;
        return 0;
    case 'x':
        if (
            compare_and_add_issue(226, fi, ar, cmdline, "xarg") ||
            compare_and_add_issue(227, fi, ar, cmdline, "xxd"))
            return 1;
        return 0;
    case 'y':
        if (
            compare_and_add_issue(228, fi, ar, cmdline, "yelp") ||
            compare_and_add_issue(229, fi, ar, cmdline, "yum"))
            return 1;
        return 0;
    case 'z':
        if (
            compare_and_add_issue(230, fi, ar, cmdline, "zip") ||
            compare_and_add_issue(231, fi, ar, cmdline, "zsh") ||
            compare_and_add_issue(232, fi, ar, cmdline, "zsoelim") ||
            compare_and_add_issue(233, fi, ar, cmdline, "zypper"))
            return 1;
        return 0;
    }
    return 0;
}

/**
 * @param id issues new id 
 * @param name name of the breakout binary
 * @param fi file information for the file 
 * @param ar struct containing all the results that enumy has found on the system
 * @param cmdline a struct continaing the runtime arguments for enumy 
 * @param search_str the string to compare the current file's name against
 */
static bool compare_and_add_issue(int id, File_Info *fi, All_Results *ar, Args *cmdline, char *search_str)
{
    if (strcmp(fi->name, search_str) == 0)
    {
        add_issue(id, fi->name, fi, ar, cmdline);
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