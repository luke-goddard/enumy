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

int has_elf_magic_bytes(File_Info *fi);
Elf_File *mmap_elf(File_Info *fi);
bool elf_parse_dynamic_sections(Elf_File *file);

static inline Elf_Ehdr *elf_header(const void *map_start);
static inline Elf_Shdr *elf_sheader(const void *map_start);
static inline Elf_Shdr *elf_section(const void *map_start, int idx);
static inline Elf_Phdr *elf_program_header(Elf_File *file);
static inline char *elf_shstr_table(const void *map_start);
Tag_Array *search_dynamic_for_value(Elf_File *file, Tag tag);
static Elf_Phdr *get_dynamic_sections_program_header(Elf_File *file);
static Elf_Off elf_dynamic_strings_offset(Elf_File *file);

void close_elf(Elf_File *elf_file, File_Info *fi);

// Test to see if the first 4 bytes of the file starts with .ELF
// the 5th byte is the architecture
// Returns 0 if not elf, 1 if 32bit elf and 2 if 64bit elf
int has_elf_magic_bytes(File_Info *fi)
{
    const int magic_size = 5;

    unsigned char values[5] = {0x00, 0x00, 0x00, 0x00};
    unsigned char little_endian[4] = {0x45, 0x7f, 0x46, 0x4c};
    unsigned char big_endian[4] = {0x7f, 0x45, 0x4c, 0x46};

    FILE *fp;
    bool little_found, big_found;

    little_found = big_found = true;

    fp = fopen(fi->location, "rb");
    if (fp == NULL)
    {
        return 0;
    }

    fread(values, 1, magic_size, fp);
    fclose(fp);

    // Little egg
    for (int i = 0; i < magic_size - 1; i++)
    {
        if (little_endian[i] != values[i])
        {
            little_found = false;
            break;
        }
    }
    // Big egg
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
        {
            return X86;
        }
        else if (values[4] == ELFCLASS64)
        {
            return X64;
        }
    }
    return 0;
}

Elf_File *parse_elf(File_Info *fi)
{
    int fd;
    Elf_File *file = NULL;

    if (
        (fi->stat->st_mode & S_IXUSR ||
         fi->stat->st_mode & S_IXGRP ||
         fi->stat->st_mode & S_IXOTH) == false)
    {
        return false;
    }

    int magic_result = has_elf_magic_bytes(fi);
    if (magic_result == 0)
    {
        return false;
    }
    if (magic_result == X64 && sizeof(char *) != 8)
    {
        return false;
    }
    if (magic_result == X86 && sizeof(char *) != 4)
    {
        return false;
    }

    if (fi->stat->st_size == 0)
    {
        return false;
    }

    fd = open(fi->location, O_RDONLY);
    if (fd < 0)
    {
        return false;
    }

    file = malloc(sizeof(Elf_File));
    if (file == NULL)
    {
        close(fd);
        return false;
    }

    file->address = mmap(NULL, fi->stat->st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    file->fi = fi;
    file->dynamic_size = 0;
    file->header = elf_header(file->address);

    if (file->header->e_ident[EI_DATA] == ELFDATA2MSB && magic_result == X64)
    {
        // TODO: Support 64 bit elf's with most significant bit first
        DEBUG_PRINT("Found a 64bit binary with most significat bit enabled, skipping parsing of this file -> %s\n", fi->location);
        close_elf(file, fi);
        return NULL;
    }

    file->sections = elf_sheader(file->address);
    if (file->sections == NULL)
    {
        DEBUG_PRINT("Failed to parse elf's section headers for file -> %s\n", fi->location);
        close_elf(file, fi);
        return NULL;
    }
    file->program_headers = elf_program_header(file);
    if (file->program_headers == NULL)
    {
        DEBUG_PRINT("Failed to parse elf's program headers for file -> %s\n", fi->location);
        close_elf(file, fi);
        return NULL;
    }

    return file;
}

bool elf_parse_dynamic_sections(Elf_File *file)
{
    // Not all ELF files have a dynamic sections
    file->dynamic_strings = elf_dynamic_strings_offset(file);
    file->dynamic_header = get_dynamic_sections_program_header(file);
    return file->dynamic_header == 0;
}

Tag_Array *search_dynamic_for_value(Elf_File *file, Tag tag)
{
    if (file->dynamic_strings == 0 || file->dynamic_header == NULL)
    {
        return NULL;
    }

    int number_of_elements = 0;
    int number_of_findings = 0;
    Elf_Internal_Dyn *entry = file->dynamic_header->p_offset + file->address;
    Elf_Internal_Dyn *entry2 = file->dynamic_header->p_offset + file->address;

    for (; (char *)(entry + 2) <= (char *)(file->dynamic_header->p_offset + file->address + file->dynamic_header->p_filesz); entry++)
    {
        if (entry->d_tag == tag)
        {
            number_of_findings++;
        }
        number_of_elements++;
        if (entry->d_tag == DT_NULL)
        {
            break;
        }
    }

    if (number_of_findings == 0)
    {
        return NULL;
    }

    Tag_Array *findings = malloc(sizeof(Tag_Array) * number_of_findings);
    if (findings == NULL)
    {
        out_of_memory_err();
    }
    findings[0].size = number_of_findings;

    int current_findings = 0;

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

void close_elf(Elf_File *elf_file, File_Info *fi)
{
    munmap((void *)elf_file->address, fi->stat->st_size);
    free(elf_file);
}

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
    {
        return NULL;
    }

    for (int i = 0; i < file->header->e_phnum; i++)
    {
        if (file->program_headers[i].p_type == PT_DYNAMIC)
        {
            return &file->program_headers[i];
        }
    }
    return NULL;
}
