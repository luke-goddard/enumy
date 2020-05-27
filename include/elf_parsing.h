/*
    The elf parsing header file is used to durning scans that 
    require the ELF to be parsed, for example the rpath scan and 
    the core dump scan. 

    To use this file you must first call parse_elf then pass this 
    Elf_File struct to other methods
*/

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

/* ============================ DEFINES ============================== */

/* Defined different elf architectures */
#define NOT_ELF 0
#define X64 2
#define X86 1

/* will be defined if the machine compiling is x64 */
#ifdef __amd64
typedef Elf64_Ehdr Elf_Ehdr;   /* 64 Bit ELF headers */
typedef Elf64_Phdr Elf_Phdr;   /* 64 Bit Program headers */
typedef Elf64_Shdr Elf_Shdr;   /* 64 Bit Section headers */
typedef Elf64_Sym Elf_Sym;     /* 64 Bit Symbol Table */
typedef Elf64_Off Elf_Off;     /* 64 Bit offset */
typedef uint64_t Elf_Addr;     /* 64 Bit ELF address */
typedef uint64_t Elf_Size;     /* 64 Bit ELF size */
typedef long unsigned int Tag; /* 64 Bit Tag */
#endif

/* will be defined if the machine compiling is x86 */
#ifdef __i386
typedef Elf32_Ehdr Elf_Ehdr;   /* 32 Bit ELF headers */
typedef Elf32_Phdr Elf_Phdr;   /* 32 Bit Program headers */
typedef Elf32_Shdr Elf_Shdr;   /* 32 Bit Section headers */
typedef Elf32_Sym Elf_Sym;     /* 32 Bit Symbol Table */
typedef Elf32_Off Elf_Off;     /* 32 Bit offset */
typedef uint32_t Elf_Addr;     /* 32 Bit ELF address */
typedef uint32_t Elf_Size;     /* 32 Bit ELF size */
typedef long unsigned int Tag; /* 32 Bit Tag */
#endif

#ifdef __ARM
// TODO: Need to get a raspberry pi first
#endif

/* GET_DYNAMIC_NAME asssumes that VALID_DYNAMIC_NAME has */
/* already been called and verified that the string exists.  */
#define GET_DYNAMIC_NAME(filedata, offset) \
    (filedata->dynamic_strings + offset)

/* ============================ STRUCTS ============================== */

/* Dynamic tags(Dyn) */
/* Used to for RPATH, RUNPATH, $ORIGIN scans */
/* The.dynamic section contains a series of structures that hold relevant */
/* dynamic linking information.The d_tag member controls the interpretation of d_un. */
typedef struct Elf_Internal_Dyn
{
    /* Main d_tag values used in enumy */
    /* DT_NULL   -> Marks end of dynamic section */
    /* DT_NEEDED -> String table offset to name of a needed library */
    /* DT_STRTAB Address of string table */
    /* DT_RPATH    String table offset to library search path (deprecated) */
    /* DT_RUNPATH  String table offset to library search path */

    Elf_Addr d_tag; /* tag value */
    union {
        Elf_Addr d_val; /* This member represents integer values with various interpretations. */
        Elf_Addr d_ptr; /* This member represents program virtual addresses. */
    } d_un;
} Elf_Internal_Dyn;

/* Struct with all the information needed to process an ELF File */
typedef struct Elf_File
{
    File_Info *fi;
    void *address;                     /* Location of mapped file in memory */
    Elf_Ehdr *header;                  /* Location of the elf's header */
    Elf_Shdr *sections;                /* Location of the elf's sections */
    Elf_Shdr *symtab;                  /* Location of the elf's symbol table */
    Elf_Phdr *program_headers;         /* Location of the elf's program headers */
    Elf_Phdr *dynamic_header;          /* Location of the elf's dynamic headers */
    Elf_Internal_Dyn *dynamic_section; /* Dynamic section */
    Elf_Size dynamic_size;             /* Numer of entries in the dynamic section */
    Elf_Off dynamic_strings;           /* Location of the elf's dynamic strings */
} Elf_File;

/* Contains value for an entry in the dynamic sections */
typedef struct Tag_Array
{
    char *tag_value; /* Contains the string pointed to via d_ptr */
    int size;        /* Size of the string */
} Tag_Array;

/* ============================ PROTOTYPES ============================== */

/**
 * Check to make sure that the file has the ELF magic bytes  
 * @param fi The struct containg the files information
 * @return X86 or X64 or NOT_ELF if the file is not an ELF 
 */
int has_elf_magic_bytes(File_Info *fi);

/**
 * This function will parse a file if got the ELF file magic bytes. Most of the structure 
 * ELF_File will be populated such as the elf headers,  program headers, section 
 * headers. 
 * @param fi The file that is going to be parsed 
 * @return NULL on Error, else a pointer to an Elf_File struct
 */
Elf_File *parse_elf(File_Info *fi);

/**
 * This function will itterate through the dynamic section and find tags that match the search 
 * criteria, any tag found will be added to a Tag_Array.
 * @param elf The Elf_File struct 
 * @param tag The dynamic tag that we're searching 
 * @return A Tag_Array with all of the search results if nothing found then returns NULL 
 */
Tag_Array *search_dynamic_for_value(Elf_File *elf, Tag tag);

/**
 * Tries to find the dynamic section of the ELF file, not all ELF files have a dynamic section
 * @param file This is the Elf_File that we're use
 * @return True if the dynamic section is found, else return False
 */
bool elf_parse_dynamic_sections(Elf_File *elf);

/**
 * This function will deallocate all of the memory required for the Elf File structure
 * This includes unmapping the mmaped file 
 * @param elf This is the struct containing the Elf Information
 * @param fi This is the file information 
 */
void close_elf(Elf_File *elf, File_Info *fi);
