/*
    This file parses ELF binaries to get their headers and sections. The we can perform 
    task like searching for RT_PATH and to test if the file is a core dump. 

    I used https://github.com/bminor/binutils-gdb/blob/master/binutils/readelf.c as a 
    starting point. It's 20k lines long. By reading it I deduced the following 

    To get the rt_path you have to parse the ELF header. This gives you the offset of 
    the program header. Inside the program header gives you a list off other headers/sections
    we can loop through until we find the dynamic header/section. Once we have found that 
    we can then loop through all the values in the dynamic table thing until we get a key called 
    DT_RUNPATH. Once we have the DT_RUNPATH key we need to search program header to find the 
    offset for the dynamic strings section. Then we add the DT_RUNPATH's key's value (offset)
    to the offset of the dynamic strings table. This gives us a null terminated string pointing
    to the run path. After that we need to find out what libaries are needed by the binary to see 
    if we can inject them. To do this instead of looking for  DT_RUNPATH we search for DT_NEEDED. 
    This gives us a list of library names. 

    elf_header -> program_header -> dynamic_header -> .dynamic -> .dynsym 
*/

#include "file_system.h"
#include "main.h"
#include "results.h"
#include "scan.h"
#include "utils.h"
#include "elf_parsing.h"
#include "debug.h"

#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>

/* ============================ PROTOTYPES ============================== */

int has_elf_magic_bytes(File_Info *fi);
void close_elf(Elf_File *elf_file, File_Info *fi);
bool elf_parse_dynamic_sections(Elf_File *file);

Elf_File *parse_elf(File_Info *fi);
Elf_File *mmap_elf(File_Info *fi);
Tag_Array *search_dynamic_for_value(Elf_File *file, Tag tag);

static Elf_Off elf_dynamic_strings_offset(Elf_File *file);
static inline Elf_Ehdr *elf_header(const void *map_start);
static inline Elf_Shdr *elf_sheader(const void *map_start);
static inline Elf_Shdr *elf_section(const void *map_start, int idx);
static inline Elf_Phdr *elf_program_header(Elf_File *file);
static inline char *elf_shstr_table(const void *map_start);
static Elf_Phdr *get_dynamic_sections_program_header(Elf_File *file);

/* ============================ FUNCTIONS ============================== */

/**
 * Check to make sure that the file has the ELF magic bytes  
 * @param fi The struct containg the files information
 * @return X86 or X64 or NOT_ELF if the file is not an ELF 
 */
int has_elf_magic_bytes(File_Info *fi)
{
    // TODO Need to re write this function as there are a few things
    // Wrong with it
    // Check the size of the file first
    // Get rid of the endian stuff
    // Use memcpy
    const int magic_size = 5;

    unsigned char values[5] = {0x00, 0x00, 0x00, 0x00};
    unsigned char little_endian[4] = {0x45, 0x7f, 0x46, 0x4c};
    unsigned char big_endian[4] = {0x7f, 0x45, 0x4c, 0x46};

    FILE *fp;
    bool little_found, big_found;

    little_found = big_found = true;

    fp = fopen(fi->location, "rb");
    if (fp == NULL)
        return 0;

    fread(values, 1, magic_size, fp);
    fclose(fp);

    // TODO USE memcpy
    for (int i = 0; i < magic_size - 1; i++)
    {
        if (little_endian[i] != values[i])
        {
            little_found = false;
            break;
        }
    }

    for (int i = 0; i < magic_size - 1; i++)
    {
        if (big_endian[i] != values[i])
        {
            big_found = false;
            break;
        }
    }
    if (little_found || big_found)
    {
        if (values[4] == ELFCLASS32)
            return X86;

        else if (values[4] == ELFCLASS64)
            return X64;
    }
    return NOT_ELF;
}

/**
 * This function will parse a file if got the ELF file magic bytes. Most of the structure 
 * ELF_File will be populated such as the elf headers,  program headers, section 
 * headers. 
 * @param fi The file that is going to be parsed 
 * @return NULL on Error, else a pointer to an Elf_File struct
 */
Elf_File *parse_elf(File_Info *fi)
{
    int fd;
    Elf_File *file = NULL;

    /* Check to see if the current file is executable and not empty*/
    if (
        (fi->stat->st_mode & S_IXUSR ||
         fi->stat->st_mode & S_IXGRP ||
         fi->stat->st_mode & S_IXOTH) == false ||
        fi->stat->st_size == 0)
        goto FAILURE;

    int magic_result = has_elf_magic_bytes(fi);

    /* Check if file is elf and matches the target arch of the current system */
    if (
        (magic_result == NOT_ELF ||
         (magic_result == X64 && sizeof(char *) != 8) || /* Elf does not match target arch */
         (magic_result == X86 && sizeof(char *) != 4)))  /* Elf does not match target arch */
        goto FAILURE;

    /* Try and open the ELF file */
    fd = open(fi->location, O_RDONLY);
    if (fd < 0)
        goto FAILURE;

    /* Try and allocate memory for the elf file */
    file = malloc(sizeof(Elf_File));
    if (file == NULL)
    {
        close(fd);
        goto FAILURE;
    }

    /* Map the elf file into memory */
    file->address = mmap(NULL, fi->stat->st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file->address == MAP_FAILED)
    {
        DEBUG_PRINT("%s\n", "Fauled to map binary into memory");
        goto FAILURE;
    }
    close(fd);

    /* Populate the Elf_Files struct pointers */
    file->fi = fi;
    file->dynamic_size = 0;
    file->header = elf_header(file->address);

    // TODO: Support 64 bit elf's with most significant bit first
    if (file->header->e_ident[EI_DATA] == ELFDATA2MSB && magic_result == X64)
    {
        DEBUG_PRINT("Found a 64bit binary with most significat bit enabled, skipping parsing of this file -> %s\n", fi->location);
        goto FAILURE_CLOSE_ELF;
    }

    /* Get the section headers */
    file->sections = elf_sheader(file->address);
    if (file->sections == NULL)
    {
        DEBUG_PRINT("Failed to parse elf's section headers for file -> %s\n", fi->location);
        goto FAILURE_CLOSE_ELF;
    }

    /* Get the program headers */
    file->program_headers = elf_program_header(file);
    if (file->program_headers == NULL)
    {
        DEBUG_PRINT("Failed to parse elf's program headers for file -> %s\n", fi->location);
        goto FAILURE_CLOSE_ELF;
    }

    /* Everything went smoothly*/
    return file;

/* Enumy failed to parse the ELF, requires investigation */
FAILURE_CLOSE_ELF:
    close_elf(file, fi);

/* Probably not an elf file */
FAILURE:
    return NULL;
}

/**
 * Tries to find the dynamic section of the ELF file, not all ELF files have a dynamic section
 * @param file This is the Elf_File that we're use
 * @return True if the dynamic section is found, else return False
 */
bool elf_parse_dynamic_sections(Elf_File *file)
{
    file->dynamic_header = 0;
    file->dynamic_strings = elf_dynamic_strings_offset(file);
    file->dynamic_header = get_dynamic_sections_program_header(file);
    return file->dynamic_header != 0;
}

/**
 * This function will itterate through the dynamic section and find tags that match the search 
 * criteria, any tag found will be added to a Tag_Array.
 * Currently the function will itterate through the symbols twice, the first time finds how many 
 * hits the search gets so that we can allocate the correct ammount of memory
 * @param file The Elf_File struct 
 * @param tag The dynamic tag that we're searching 
 * @return A Tag_Array with all of the search results if nothing found then returns NULL 
 */
Tag_Array *search_dynamic_for_value(Elf_File *file, Tag tag)
{
    int number_of_elements = 0; /* Total number of tags */
    int number_of_findings = 0; /* Total number of matching tags */
    int current_findings = 0;

    /* Make sure that the Elf_File has been parsed */
    if (file->dynamic_strings == 0 || file->dynamic_header == NULL)
        return NULL;

    /* We search twice so we need two pointers */
    Elf_Internal_Dyn *entry = file->dynamic_header->p_offset + file->address;
    Elf_Internal_Dyn *entry2 = file->dynamic_header->p_offset + file->address;

    /* Loop through the dynamic section until we find DT_NULL, this signifies that we've reached the end */
    // TODO corrupt ELF Files could break this if no DT_NULL is present
    for (; (char *)(entry + 2) <= (char *)(file->dynamic_header->p_offset + file->address + file->dynamic_header->p_filesz); entry++)
    {
        /* Current tag is equal to the search value */
        if (entry->d_tag == tag)
            number_of_findings++;

        number_of_elements++;

        /* End of the dynamic section */
        if (entry->d_tag == DT_NULL)
            break;
    }

    /* Did not find any matching tags */
    if (number_of_findings == 0)
        return NULL;

    /* Allocate memory for the return results */
    Tag_Array *findings = malloc(sizeof(Tag_Array) * number_of_findings);
    if (findings == NULL)
        out_of_memory_err();

    /* Set the array size */
    findings[0].size = number_of_findings;

    /* Loop through the second time, this time adding items to the Tag_Array */
    for (int i = 0; i < number_of_elements; i++)
    {
        if (entry2->d_tag == tag)
        {
            findings[current_findings].tag_value = file->address + file->dynamic_strings + entry2->d_un.d_ptr;
            current_findings++;
        }
        entry2++;
    }
    return findings;
}

/**
 * This function will deallocate all of the memory required for the Elf File structure
 * This includes unmapping the mmaped file 
 * @param elf_file This is the struct containing the Elf Information
 * @param fi This is the file information 
 */
void close_elf(Elf_File *elf_file, File_Info *fi)
{
    munmap((void *)elf_file->address, fi->stat->st_size);
    free(elf_file);
}

/* ============================ STATIC FUNCTIONS ============================== */

static inline Elf_Ehdr *elf_header(const void *map_start)
{
    return (Elf_Ehdr *)map_start;
}

static inline Elf_Shdr *elf_sheader(const void *map_start)
{
    return (Elf_Shdr *)((Elf_Addr)elf_header(map_start) + (Elf_Off)elf_header(map_start)->e_shoff);
}

static inline Elf_Shdr *elf_section(const void *map_start, int idx)
{
    return &elf_sheader(map_start)[idx];
}

static inline char *elf_shstr_table(const void *map_start)
{
    if (elf_header(map_start)->e_shstrndx == SHN_UNDEF)
        return NULL;
    return (char *)map_start + (int)(elf_section(map_start, elf_header(map_start)->e_shstrndx))->sh_offset;
}

static inline Elf_Phdr *elf_program_header(Elf_File *file)
{
    return (Elf_Phdr *)(file->address + file->header->e_phoff);
}

// This function searches for the section pointing to the dynamic string offset
// This function is takes up around 63% of CPU time, because elf files can have
// thousands of sections.
static Elf_Off elf_dynamic_strings_offset(Elf_File *file)
{
    if (file->header->e_shnum + ((Elf_Addr)file->sections - (Elf_Addr)file->address) > (long unsigned int)file->fi->stat->st_size)
    {
        DEBUG_PRINT("Failed parse elf's sections, offset is bigger than mapped memory -> %s\n", file->fi->location);
        return 0;
    }
    for (Elf_Off i = 0; i < file->header->e_shnum; i++)
    {
        if (file->sections[i].sh_type == SHT_STRTAB)
        {
            if (file->sections[i].sh_offset > (long unsigned int)file->fi->stat->st_size)
            {
                DEBUG_PRINT("Failed parse elf's dynamic strings, offset is bigger than mapped memory -> %s\n", file->fi->location);
                return 0;
            }
            return file->sections[i].sh_offset;
        }
    }
    return 0;
}

static Elf_Phdr *get_dynamic_sections_program_header(Elf_File *file)
{
    if (file->header == NULL || file->program_headers == NULL)
        return NULL;

    for (int i = 0; i < file->header->e_phnum; i++)
    {
        if (file->program_headers[i].p_type == PT_DYNAMIC)
            return &file->program_headers[i];
    }
    return NULL;
}
