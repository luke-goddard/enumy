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
#include "elf_parsing.h"
#include "error_logger.h"
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
bool elf_parse_dynamic_sections(Elf_File *elf);

Elf_File *parse_elf(All_Results *ar, File_Info *fi);
Elf_File *mmap_elf(File_Info *fi);
Tag_Array *search_dynamic_for_value(Elf_File *elf, Tag tag);

static Elf_Off elf_dynamic_strings_offset(Elf_File *elf);
static inline Elf_Ehdr *elf_header(const void *map_start);
static inline Elf_Shdr *elf_sheader(const void *map_start);
static inline Elf_Shdr *elf_section(const void *map_start, int idx);
static inline Elf_Phdr *elf_program_header(Elf_File *elf);
static Elf_Phdr *get_dynamic_sections_program_header(Elf_File *elf);

/* ============================ FUNCTIONS ============================== */

/**
 * Check to make sure that the file has the ELF magic bytes  
 * @param fi The struct containg the files information
 * @return X86 or X64 or NOT_ELF if the file is not an ELF 
 */
int has_elf_magic_bytes(File_Info *fi)
{
    /* ============================ TODO ============================== */
    // TODO Need to re write this function as there are a few things
    // Wrong with it
    // Check the size of the file first
    // Get rid of the endian stuff
    // Use memcpy
    // Get the architecture from the ELF headers
    /* ============================ TODO ============================== */
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
Elf_File *parse_elf(All_Results *ar, File_Info *fi)
{
    int fd;
    Elf_File *elf = NULL;

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
    elf = malloc(sizeof(Elf_File));
    if (elf == NULL)
    {
        close(fd);
        goto FAILURE;
    }

    /* Map the elf file into memory */
    elf->address = mmap(NULL, fi->stat->st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (elf->address == MAP_FAILED)
    {
        log_error_errno(ar, "Failed to map binary into memory", errno);
        goto FAILURE_CLOSE_ELF;
    }

    /* Populate the Elf_Files struct pointers */
    elf->fi = fi;
    elf->dynamic_size = 0;
    elf->header = elf_header(elf->address);

    // TODO: Support 64 bit elf's with most significant bit first
    if (elf->header->e_ident[EI_DATA] == ELFDATA2MSB && magic_result == X64)
    {
        log_error_loc(ar, "Found 64 bit binary with most significant bit first enabled", fi->location);
        goto FAILURE_CLOSE_ELF;
    }

    /* Get the section headers */
    elf->sections = elf_sheader(elf->address);
    if (elf->sections == NULL)
    {
        log_error_loc(ar, "Failed to parse elf's section headers", fi->location);
        goto FAILURE_CLOSE_ELF;
    }

    /* Get the program headers */
    elf->program_headers = elf_program_header(elf);
    if (elf->program_headers == NULL)
    {
        log_error_loc(ar, "Failed to parse elf's program headers", fi->location);
        goto FAILURE_CLOSE_ELF;
    }

    /* Everything went smoothly */
    return elf;

/* Enumy failed to parse the ELF, requires investigation */
FAILURE_CLOSE_ELF:
    close_elf(elf, fi);

/* Probably not an elf file */
FAILURE:
    return NULL;
}

/**
 * Tries to find the dynamic section of the ELF file, not all ELF files have a dynamic section
 * @param elf This is the Elf_File that we're use
 * @return True if the dynamic section is found, else return False
 */
bool elf_parse_dynamic_sections(Elf_File *elf)
{
    elf->dynamic_header = 0;
    elf->dynamic_strings = elf_dynamic_strings_offset(elf);
    elf->dynamic_header = get_dynamic_sections_program_header(elf);
    return elf->dynamic_header != 0;
}

/**
 * This function will itterate through the dynamic section and find tags that match the search 
 * criteria, any tag found will be added to a Tag_Array.
 * Currently the function will itterate through the symbols twice, the first time finds how many 
 * hits the search gets so that we can allocate the correct ammount of memory
 * @param elf The Elf_File struct 
 * @param tag The dynamic tag that we're searching 
 * @return A Tag_Array with all of the search results if nothing found then returns NULL 
 */
Tag_Array *search_dynamic_for_value(Elf_File *elf, Tag tag)
{
    int number_of_elements = 0; /* Total number of tags */
    int number_of_findings = 0; /* Total number of matching tags */
    int current_findings = 0;

    /* Make sure that the Elf_File has been parsed */
    if (elf->dynamic_strings == 0 || elf->dynamic_header == NULL)
        return NULL;

    /* ============================ TODO ============================== */
    /* elf->address is a void ptr, so pointer arithmatics is undefined  */
    /* ============================ TODO ============================== */

    /* We search twice so we need two pointers */
    Elf_Internal_Dyn *entry = elf->dynamic_header->p_offset + elf->address;
    Elf_Internal_Dyn *entry2 = elf->dynamic_header->p_offset + elf->address;

    /* ============================ TODO ============================== */
    /* This function could fail is no DT_NULL is found  (corrupted elf) */
    /* ============================ TODO ============================== */

    /* Loop through the dynamic section until we find DT_NULL, this signifies that we've reached the end */
    for (; (char *)(entry + 2) <= (char *)(elf->dynamic_header->p_offset + elf->address + elf->dynamic_header->p_filesz); entry++)
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
    {
        log_fatal_errno("Failed to allocate memory for the tag array", errno);
        exit(EXIT_FAILURE);
    }

    /* Set the array size */
    findings[0].size = number_of_findings;

    /* Loop through the second time, this time adding items to the Tag_Array */
    for (int i = 0; i < number_of_elements; i++)
    {
        if (entry2->d_tag == tag)
        {
            findings[current_findings].tag_value = elf->address + elf->dynamic_strings + entry2->d_un.d_ptr;
            current_findings++;
        }
        entry2++;
    }
    return findings;
}

/**
 * This function will deallocate all of the memory required for the Elf File structure
 * This includes unmapping the mmaped file 
 * @param elf This is the struct containing the Elf Information
 * @param fi This is the file information 
 */
void close_elf(Elf_File *elf, File_Info *fi)
{
    munmap((void *)elf->address, fi->stat->st_size);
    free(elf);
}

/* ============================ STATIC FUNCTIONS ============================== */

/**
 * Get's the location of the ELF headers 
 * @param map_start This is the base address of the mmaped ELF file
 * @return The offset of the elf headers 
 */
static inline Elf_Ehdr *elf_header(const void *map_start)
{
    return (Elf_Ehdr *)map_start;
}

/**
 * Get's the location of the  ELF section headers 
 * e_shoff is the section_header_offset we can just add this too the ELF's base addess 
 * @param map_start This is the base address of the mmaped ELF file 
 * @return The offset of the elf section headers 
 */
static inline Elf_Shdr *elf_sheader(const void *map_start)
{
    return (Elf_Shdr *)((Elf_Addr)elf_header(map_start) + (Elf_Off)elf_header(map_start)->e_shoff);
}

/**
 * Get the elf section offset for idx postioned section
 * @param map_start This is the base address of the mmaped ELF file 
 * @param idx This is the section header table index for the section that we're interested in
 * @return The offset for the elf section at position idx
 */
static inline Elf_Shdr *elf_section(const void *map_start, int idx)
{
    return &elf_sheader(map_start)[idx];
}

/**
 * finds the program headers 
 * @param elf This is the elf file that has alredy been partially parsed
 * @return The offset of the ELF's program headers
 */
static inline Elf_Phdr *elf_program_header(Elf_File *elf)
{
    return (Elf_Phdr *)(elf->address + elf->header->e_phoff);
}

/**
 * This file will search through the elf file sections until it finds the SHT_STRTAB (string table) section
 * Once the string table offset has been found we will return it. The offset is obvious architecture dependent 
 * When using the offset you will have to add it to the mapped memories base address  
 * NOTE: This function is extremely CPU intrestive
 * @param elf This is the parsed elf file 
 * @return 0 if the offset is not found or a None 0 offset on success
 */
static Elf_Off elf_dynamic_strings_offset(Elf_File *elf)
{
    /* Find the number of elf sections and make sure that we do not got out of bounds of the mmaped memory */
    if (elf->header->e_shnum + ((Elf_Addr)elf->sections - (Elf_Addr)elf->address) > (long unsigned int)elf->fi->stat->st_size)
    {
        DEBUG_PRINT("Failed parse elf's sections, offset is bigger than mapped memory -> %s\n", elf->fi->location);
        return 0;
    }

    /* Loop through all the elf headers until we run out of headers or find the string table entry*/
    for (Elf_Off i = 0; i < elf->header->e_shnum; i++)
    {
        if (elf->sections[i].sh_type == SHT_STRTAB)
        {
            /* Another check to see if the offset is within the range of the mapped memory */
            if (elf->sections[i].sh_offset > (long unsigned int)elf->fi->stat->st_size)
            {
                DEBUG_PRINT("Failed parse elf's dynamic strings, offset is bigger than mapped memory -> %s\n", elf->fi->location);
                goto NOTHING_FOUND;
            }
            /* Return the string table offset */
            return elf->sections[i].sh_offset;
        }
    }
NOTHING_FOUND:
    return 0;
}

/**
 * This function will try and find the dynamic section in the program headers 
 * @param elf This is the ELF file that has been parsed 
 * @return Null if not found else the offset of the program header that points to the dynamic section 
 */
static Elf_Phdr *get_dynamic_sections_program_header(Elf_File *elf)
{
    /* Sanity check we have parsed the ELF file */
    if (elf->header == NULL || elf->program_headers == NULL)
        return NULL;

    /* Itterate through the headers until we find the header */
    /* that points to the dynamic section */
    for (int i = 0; i < elf->header->e_phnum; i++)
    {
        if (elf->program_headers[i].p_type == PT_DYNAMIC)
            return &elf->program_headers[i];
    }

    /* Failed to find the dynamic section */
    return NULL;
}
