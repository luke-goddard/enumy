/* 
    This file contains all the scans that can be run on a given file found 
    when walking the file systems. Most of theses scans relate to insecure 
    permissions

    The permission of proceses that is executing a GUID or SUID binary is 
    elevated or de-elevated at run time based of the owner or group attached 
    to the file. This means that they're a great target to try and exploit. 
    SUID/GUID binaries are not insecure, but an insecuritys can be exploited 
    resulting in higher impact vulnerability
*/

#include "results.h"
#include "file_system.h"
#include "scan.h"
#include "main.h"

#include <stdio.h>
#include <string.h>

/* ============================ CONSTANTS ============================== */

char *KnownGoodSuids[] = {
    "sudo", "ping", "mount", "umount", "fusermount3", "chfn", "expiry", "change",
    "unix_chkpwd", "su", "newgrp", "passwd", "pkexec", "ksu", "nvidia-modprobe",
    "gpasswd", "mount.cifs", "chsh", "suexec", "sg", "vmware-mount",
    "vmware-vmx-debug", "vmware-vvmx-stats", "snap-confine", "mail-dotlock",
    "ssh-keysign", "polkit-agent-helper-1", "chrome-sandbox", "pam_extrausers_chkpwd",
    "chage", "ssh-agent", "wall", "vmware-authd", "fusermount", "locate", "write",
    "vmware-vmx-stats", "Xorg.wrap", "VBoxNetDHCP", "VBoxNetNAT", "VBoxSDL",
    "VBoxHeadless", "VBoxNetAdpCtl", "vmware-vmx", "VirtualBoxVM"};

/* ============================ PROTOTYPES ============================== */

int suid_bit_scan(File_Info *fi, All_Results *ar);
int guid_bit_scan(File_Info *fi, All_Results *ar);

static bool has_normal_suid_name(File_Info *fi);
static bool has_suid_and_global_write(File_Info *fi, All_Results *ar);
static bool has_suid_and_group_write(File_Info *fi, All_Results *ar);
static bool has_guid_and_global_write(File_Info *fi, All_Results *ar);
static bool has_guid_and_group_write(File_Info *fi, All_Results *ar);

/* ============================ FUNCTIONS ============================== */

/**
 * This scan will determine if the current file is an SUID file and then check
 * the permissions of this file to make sure that they're not too loose.
 * If the file is an SUID binary then we will call the  break_out_binary_scan()
 * @param fi This is the current file that's going to be scanned 
 * @param ar This is the structure that holds the link lists with the results 
 */
int suid_bit_scan(File_Info *fi, All_Results *ar)
{
    int findings = 0;
    char *name = "Abnormal SUID enabled executable found";

    /* Ignore non interesting binaries */
    if (
        !has_suid(fi) ||
        !has_global_execute(fi) ||
        (has_normal_suid_name(fi) && !has_global_write(fi)))
        goto END;

    findings++;

    /* Abnormal SUID found */
    add_issue(MEDIUM, CTF, fi->location, ar, name, "");

    if (has_suid_and_global_write(fi, ar))
        findings++;

    if (has_suid_and_group_write(fi, ar))
        findings++;

    findings += break_out_binary_scan(fi, ar);
END:
    return findings;
}

/**
 * This scan will determine if the current file is an GUID file and then check
 * the permissions of this file to make sure that they're not too loose.
 * If the file is an GUID binary then we will call the  break_out_binary_scan()
 * @param fi This is the current file that's going to be scanned 
 * @param ar This is the structure that holds the link lists with the results 
 */
int guid_bit_scan(File_Info *fi, All_Results *ar)
{
    int findings = 0;
    char *name = "Abnormal GUID enabled executable found";

    if (
        !has_guid(fi) ||
        !has_global_execute(fi) ||
        (has_normal_suid_name(fi) && !has_global_write(fi)))
        return findings;

    findings++;

    /* Abnormal GUID found */
    add_issue(MEDIUM, CTF, fi->location, ar, name, "");

    if (has_guid_and_global_write(fi, ar))
        findings++;

    if (has_guid_and_group_write(fi, ar))
        findings++;

    return findings;
}

/* ============================ STATIC FUNCTIONS ============================== */

/**
 * Tests to see if the current file is a standard SUID file
 * @param fi A struct containing the files information 
 * @return true if the SUID file matches a whitelist of known 'ok' suid files
 */
static bool has_normal_suid_name(File_Info *fi)
{
    int size = sizeof KnownGoodSuids / sizeof KnownGoodSuids[0];
    for (int x = 0; x < size; x++)
    {
        if (strcmp(fi->name, KnownGoodSuids[x]) == 0)
            return true;
    }
    return false;
}

/**
 * Tests to see if the SUID file has global write
 * @param fi A struct containing the files information 
 * @param ar a struct containing all of the results that enumy has previously found
 * @return true if it does
 */
static bool has_suid_and_global_write(File_Info *fi, All_Results *ar)
{
    char *name = "SUID enabled executable with global write access";
    if (!has_global_write(fi))
        return false;

    add_issue(HIGH, CTF, fi->location, ar, name, "");

    return true;
}

/**
 * Tests to see if the GUID file has global write
 * @param fi A struct containing the files information 
 * @param ar a struct containing all of the results that enumy has previously found
 * @return true if the file has group write
 */
static bool has_suid_and_group_write(File_Info *fi, All_Results *ar)
{
    char *name = "SUID enabled executable with group write access";
    if (!has_group_write(fi))
        return false;

    add_issue(HIGH, CTF, fi->location, ar, name, "");
    return true;
}

/**
 * Tests to see if the GUID file has group write
 * @param fi A struct containing the files information 
 * @param ar a struct containing all of the results that enumy has previously found
 * @return true if the file has global write enabled
 */
static bool has_guid_and_global_write(File_Info *fi, All_Results *ar)
{
    char *name = "GUID enabled executable with global write access";
    if (!has_global_write(fi))
        return false;

    add_issue(HIGH, CTF, fi->location, ar, name, "");
    return true;
}

/**
 * Test to see if the GUID file has group write
 * @param fi A struct containing the files information 
 * @param ar a struct containing all of the results that enumy has previously found
 * @return true if the file has group write enabled
 */
static bool has_guid_and_group_write(File_Info *fi, All_Results *ar)
{
    char *name = "GUID enabled executable with group write access";
    if (!has_group_write(fi))
        return false;

    add_issue(HIGH, CTF, fi->location, ar, name, "");
    return true;
}