/* 
    This file is meant to try and find core dump files

    Core dump file can be found by mapping the file into memory 
    inside of the Elf's elf header there is a value called e_type
    this value tells the kernel what type of elf file this is 
    if the file's elf type is set to ET_CORE, then we can report 
    this as an issue. This is because core dumps should not 
    be allowed to exist on a production machine. Core dumps can
    allow an attacker to develop zero days and if the core dump 
    file contains an sensitive data relating to passwords crypto
    etc, then an attacker can find this information to further 
    compromise the target machine. 
*/

#define _GNU_SOURCE

#include "file_system.h"
#include "main.h"
#include "results.h"
#include "scan.h"
#include "elf_parsing.h"
#include "debug.h"
#include "error_logger.h"

#include <stdio.h>
#include <err.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>

/* ============================ PROTOTYPES ============================== */

int core_dump_scan(File_Info *fi, All_Results *ar);

static void add_issue_wrapper(File_Info *fi, int severity, All_Results *ar, char *issue_name);

/* ============================ FUNCTIONS ============================== */

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
int core_dump_scan(File_Info *fi, All_Results *ar)
{
    int findings = 0;

    /* Check to see if core is in the filename */
    if (strcasestr(fi->name, "core") == NULL)
        goto RET;

    /* Return if not an ELF file */
    int arch = has_elf_magic_bytes(fi);
    if (
        (arch == NOT_ELF) ||
        (arch == X86 && sizeof(char *) != 4) ||
        (arch == X64 && sizeof(char *) != 8))
        goto RET;

    /* Parse the elf file */
    Elf_File *elf = parse_elf(ar, fi);
    if (elf == NULL)
    {
        /* Parse elf will log the err */
        goto RET;
    }

    /* Do the test to see if its a core dump file */
    if ((unsigned short)elf->header->e_type == (unsigned short)ET_CORE)
    {
        findings++;

        if (has_global_read(fi))
            add_issue_wrapper(fi, HIGH, ar, "Found a world readable coredump file");

        if (can_read(fi))
            add_issue_wrapper(fi, HIGH, ar, "Found a readable core dump file");

        if (fi->stat->st_uid != 0)
            add_issue_wrapper(fi, LOW, ar, "Found a coredump file, root is not the owner");
    }

    close_elf(elf, fi);
RET:
    return findings;
}

/* ============================ STATIC  ============================== */

/**
 * Wrapper function to raise the issue
 * @param id The issue id
 * @param fi The current file's information 
 * @param ar The struct containing all of the resutls 
 * @param issue_name The name to save the issue as 
 */
static void add_issue_wrapper(File_Info *fi, int severity, All_Results *ar, char *issue_name)
{
    add_issue(severity, CTF, fi->location, ar, issue_name, "Core dump files are used to debug crashed processes and can contain valuable information");
}