/*
    The idea of this scan is to look for files on the file system that 
    have strange permissions. For example the files UID/GUID does not 
    exist. Or global writable files in /root /boot etc. Because this 
    scan has the potential to produce loads of results it is disabled 
    in the quick scan mode and has to be enabled in the full scan mode. 

    1. Check system files are not global writable
    2. Check that files have a valid UID/GUID that exists
    3. Check that files owned in /home/user_n are onwed by user_n 
*/

#include "file_system.h"
#include "results.h"
#include "scan.h"
#include "error_logger.h"
#include "main.h"

/* ============================ CONSTS ============================== */

/* It's bad practice to have global write enabled on files in these directories */
const char *BadGlobalWriteDirs[] = {
    "/boot/", "/root/", "/etc/", "/opt/", "/proc/", "/run/", "/srv/", "/sys/", "/usr/", "/var/"};

/* ============================ PROTOTYPES ============================== */

/* ============================ FUNCTIONS  ============================== */

// void permissions_scan(All_Results *ar, File_Info *fi, Args *cmdline)
// {
// }