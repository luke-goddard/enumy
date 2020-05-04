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

#include <stdio.h>
#include <err.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>

int core_dump_scan(File_Info *fi, All_Results *ar, Args *cmdline);

/**
 * Given a file, this will test to see if the file is an elf and it's
 * parsable. Then we test to see if the file is a core dump file 
 * If the file is a core dump file then we test the permissions of the 
 * file and raise issues 
 * Note this currently cannot parse x64 MSB elf files 
 * @param fi file information struct for the current file 
 * @param ar a struct containing all of the results that enumy has found 
 * @param cmdline a struct containing the command line arguments 
 */
int core_dump_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;

    if (strcasestr(fi->name, "core") == NULL)
    {
        return findings;
    }

    int arch = has_elf_magic_bytes(fi);
    if (
        (arch == 0) ||
        (arch == X86 && sizeof(char *) != 4) ||
        (arch == X64 && sizeof(char *) != 8))
    {
        return findings;
    }

    Elf_File *elf = parse_elf(fi);
    if (elf == NULL)
    {
        DEBUG_PRINT("Failed to parse elf at location -> %s\n", fi->location);
        return findings;
    }

    // Test if the elf file is a core dump
    if ((unsigned short)elf->header->e_type == (unsigned short)ET_CORE)
    {
        findings++;

        if (has_global_read(fi))
        {
            char *name = "Found a world readable core dump file";
            Result *new_result = create_new_issue();
            set_id_and_desc(43, new_result);
            set_issue_location(fi->location, new_result);
            set_issue_name(name, new_result);
            add_new_result_high(new_result, ar, cmdline);
        }
        if (fi->stat->st_uid != 0)
        {
            char *name = "Found a core dump, owner is not root";
            Result *new_result = create_new_issue();
            set_id_and_desc(44, new_result);
            set_issue_location(fi->location, new_result);
            set_issue_name(name, new_result);
            add_new_result_low(new_result, ar, cmdline);
        }
        if (can_read(fi))
        {
            char *name = "Found a readable core dump file";
            Result *new_result = create_new_issue();
            set_id_and_desc(44, new_result);
            set_issue_location(fi->location, new_result);
            set_issue_name(name, new_result);
            add_new_result_high(new_result, ar, cmdline);
        }
    }

    close_elf(elf, fi);
    return findings;
}
