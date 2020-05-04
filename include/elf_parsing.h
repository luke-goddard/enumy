#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "main.h"
#include "results.h"
#include "scan.h"
#include "file_system.h"

#include <stdio.h>
#include <err.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>

#define X64 2
#define X86 1

#ifdef __amd64
typedef Elf64_Ehdr Elf_Ehdr; // Elf Header
typedef Elf64_Phdr Elf_Phdr; // Program Header
typedef Elf64_Shdr Elf_Shdr; // Section header
typedef Elf64_Sym Elf_Sym;   // Symbols
typedef Elf64_Off Elf_Off;
typedef uint64_t Elf_Addr;
typedef uint64_t Elf_Size;
typedef long unsigned int Tag;
// #define ARCH X64;
#endif

#ifdef __i386
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Sym Elf_Sym;
typedef Elf32_Off Elf_Off;
typedef uint32_t Elf_Addr;
typedef uint32_t Elf_Size;
typedef long unsigned int Tag;
#endif

#ifdef __ARM
// TODO:
#endif

/* GET_DYNAMIC_NAME asssumes that VALID_DYNAMIC_NAME has
   already been called and verified that the string exists.  */
#define GET_DYNAMIC_NAME(filedata, offset) \
    (filedata->dynamic_strings + offset)

typedef struct Elf_Internal_Dyn
{
    Elf_Addr d_tag; /* entry tag value */
    union {
        Elf_Addr d_val;
        Elf_Addr d_ptr;
    } d_un;
} Elf_Internal_Dyn;

typedef struct Elf_File
{
    File_Info *fi;
    void *address;                     // Location of mapped file in memory
    Elf_Ehdr *header;                  // Location of the elf's header
    Elf_Shdr *sections;                // Location of the elf's sections
    Elf_Shdr *symtab;                  // Location of the elf's symbol table
    Elf_Phdr *program_headers;         // Location of the elf's program headers
    Elf_Phdr *dynamic_header;          // Location of the elf's dynamic headers
    Elf_Internal_Dyn *dynamic_section; // Dynamic section
    Elf_Size dynamic_size;             // Numer of entries in the dynamic section
    Elf_Off dynamic_strings;           // Location of the elf's dynamic strings

} Elf_File;

typedef struct Tag_Array
{
    char *tag_value;
    int size;
} Tag_Array;

Tag_Array *search_dynamic_for_value(Elf_File *file, Tag tag);
void close_elf(Elf_File *elf_file, File_Info *fi);
int has_elf_magic_bytes(File_Info *fi);
Elf_File *parse_elf(File_Info *fi);

// This function takes a long time to execute
bool elf_parse_dynamic_sections(Elf_File *file);