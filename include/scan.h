/*
    This header file exposes all of the scanning functionality
    There are two main types of scans currently, file scans and system scans 

    File scans 
    File scans require a file as the argument. The file is not the file 
    path but a File_Info struct. This struct is populated in file_system.c
    when the file system is walked. Each file found during the walk is added to 
    a thread pool and the file scannes are called. 

    System scan
    System scans run in a seperate thread because they are more asyncronous in nature
    as they have no dependencies on walking the file system. The system scans do not use
    any files found durning the walk and are invoked in the all_scans.c file 
*/

#pragma once

#include "results.h"
#include "file_system.h"
#include "main.h"

/* ============================ PROTOTYPES ============================== */

/* ============================ ENTRY POINT FUNCTIONS =================== */

/**
 * This is the main entry point to kick off all of the scans. This function will create a 
 * thread for the file scans and then run the system scans in the current thread.
 * @param results this is a structure containing linked lists for the results to be stored 
 * @param args This is the run time arguments specified by the user 
 */
void start_scan(All_Results *results, Args *args);

/** 
 * This kicks of all the scans for the current file found by walking the file system in a seperate thread 
 * @param thread_pool_args this is structure containing all the information needed to kick off the scan
 */
void scan_file_for_issues(Thread_Pool_Args *thread_pool_args);

/* ============================ FILE SCANS ============================== */

/**
 * Linux systems have tried to discurage the use of SUID binaries because they're 
 * so dangerous if they're exploitable. One way Linux has combated this is with Linux 
 * capabilities. This gives the executable the option to a smaller subset of the powers
 * that root would have, minimizing the damage that can be done if the binary is exploited
 * @param fi This is the current file that's going to be scanned 
 * @param ar This is the structure that holds the link lists with the results 
 * @param args This is the runtime arguments needed for the scan
 */
int capabilities_scan(File_Info *fi, All_Results *ar, Args *cmdline);

/**
 * The elf file format specifies that the names of shared objects required for the executable 
 * to be run should be stored in the dynamic section of the ELF file. This scan will try and parse 
 * the elf file to see if any of those shared objects are missing, writable. If the shared object 
 * is missing we can also check to see if the RPATH or RUNPATH is specified in the binary. There
 * is a small chance that this location is writable by the current user meaning that we can 
 * inject arbitrary code into a stub shared object and load that instead. If that ELF file is 
 * called by a root user/process then we can comprimise the entire system. 
 * @param fi This is the current file that's going to be scanned 
 * @param ar This is the structure that holds the link lists with the results 
 * @param args This is the runtime arguments needed for the scan
 */
int rpath_scan(File_Info *fi, All_Results *ar, Args *cmdline);

/**
 * This is more a generic scan that tries to clasify the current file based of trivial things 
 * like file extensions and the contents of this file. The scan will look for config files containing 
 * passwords, encryption keys, backup files etc. 
 * @param fi This is the current file that's going to be scanned 
 * @param ar This is the structure that holds the link lists with the results 
 */
int intresting_files_scan(File_Info *fi, All_Results *ar);

/**
 * Note you should only call this scan if the current file is know to be an SUID 
 * 
 * This scan is used to try and find dangorous SUID binaries that can be exploited 
 * by the current user to gain a higher privilaged account. This list was largely inspired by 
 * https://gtfobins.github.io/
 * @param fi This is the current file that's going to be scanned 
 * @param ar This is the structure that holds the link lists with the results 
 */
int break_out_binary_scan(File_Info *fi, All_Results *ar);

/**
 * This scan will try and determine if the current file is an elf file. 
 * There are many different types of ELF files, one of them is called a core dump file 
 * These files are used durning debugging buy tools like GDB. The contents of a core dump
 * file contain the running process's memory at the time of a crash. This means that contents 
 * of these files could contain useful information such as encryption keys stored in memory 
 * or even better, all the information needed to replicate a crash and develop a zero day exploit 
 * @param fi This is the current file that's going to be scanned 
 * @param ar This is the structure that holds the link lists with the results 
 */
int core_dump_scan(File_Info *fi, All_Results *ar);

/**
 * This scan will determine if the current file is an SUID file and then check
 * the permissions of this file to make sure that they're not too loose.
 * If the file is an SUID binary then we will call the  break_out_binary_scan()
 * @param fi This is the current file that's going to be scanned 
 * @param ar This is the structure that holds the link lists with the results 
 */
int suid_bit_scan(File_Info *fi, All_Results *ar);

/**
 * This scan will determine if the current file is an GUID file and then check
 * the permissions of this file to make sure that they're not too loose.
 * If the file is an GUID binary then we will call the  break_out_binary_scan()
 * @param fi This is the current file that's going to be scanned 
 * @param ar This is the structure that holds the link lists with the results 
 */
int guid_bit_scan(File_Info *fi, All_Results *ar);

/**
 * (lotl) Living off the land is technique used by hackers to utilize files  
 * found on the system to reduce noise, increase stealth and perform useful tasks 
 * This scan will look for common files such as netcat, gcc etc that can be usful 
 * durning a pentest.
 * @param fi This is the current file that's going to be scanned 
 * @param ar This is the structure that holds the link lists with the results 
 */
void lotl_scan(File_Info *fi, All_Results *ar);

/**
 * This scan will check the current for for common weak permissions
 * @param ar This is a struct containing enumy's results
 * @param fi This is the current file that is going to be scanned
 */
void permissions_scan(File_Info *fi, All_Results *ar, vec_void_t *users);

/* ============================ SYSTEM SCANS ============================== */

/**
 * This scan will look at kerenl parameters in /proc/sys
 * The values of these parameters can have major implications on the security
 * of product machines for example, ASLR should always be enabled on modern
 * systems. There are plenty of other parameters that would probably be ignored 
 * unless you're doing a very in depth pentest
 * @param ar This is the structure that holds the link lists with the results 
 */
void sys_scan(All_Results *ar);

/**
 * SSH is widely used and it very common for ssh to be configured insecurly
 * this scan will look for common misconfiguration such as being able to log 
 * into SSH directly as root user
 * @param ar This is the structure that holds the link lists with the results 
 */
void sshd_conf_scan(All_Results *all_results);

/**
 * This is not really a scan but will display the output of some useful bash commands
 * heavily inspired by the popular LinEnum.sh script found at https://github.com/rebootuser/LinEnum
 * The idea of this is give the analyst some useful information to look at while waiting for the scan
 * to complete. Currently the output from this scan is NOT saved in the final results.
 */
void current_user_scan();

/**
 * This function will read and parse the /etc/passwd file and then run various 
 * scans against the contents of this file.
 * @param ar Enumy's results struct
 * @return Returns a vector containing pointers to Parsed_Passwd_line
 */
vec_void_t *passwd_scan(All_Results *ar);

/* ============================ CLEAN UP FUNCTIONS ============================== */

/**
 * Deallocates the memory used by calling passwd_scan
 * @param users vector containing pointers to Parsed_Passwd_line
 */
void free_users(vec_void_t *users);

/**
 * This scan will look check the kerenel version to see if it's out of datae 
 * if it is out date, then we will report any POC exploits that match the kerenel
 * version
 * @param ar This is the enumy results struct
 */
void scan_kernel_exploits(All_Results *ar);

/**
 * This scan will check what security is in place for mounted file systems
 * Common security practice is to have encrypted mount points for each area
 * read only mounts and addtional parameters set to prevent an intruder from 
 * gaining further access
 * @param ar A structure containing enumy's results
 */
void file_system_scan(All_Results *ar);