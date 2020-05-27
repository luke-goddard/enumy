/*
    The job of this file is to try and identify files that could be 
    of intrest to an attacker without showing too many false positives
    Examples of these files are backupfiles, private keys, certificates,
    writable config files and coredump files. 
*/

#define _GNU_SOURCE

#include "main.h"
#include "results.h"
#include "utils.h"
#include "file_system.h"
#include "elf_parsing.h"
#include "debug.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

/* ============================ DEFINES ============================== */

#define ENTROPY_SIZE 5000

/* ============================ PROTOTYPES ============================== */

int intresting_files_scan(File_Info *fi, All_Results *ar, Args *cmdline);

static int extension_checker(File_Info *fi, All_Results *ar, Args *cmdline);
static int file_name_checker(File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_for_encryption_key(File_Info *fi, All_Results *ar, Args *cmdline);
static int check_for_writable_shared_object(File_Info *fi, All_Results *ar, Args *cmdline);
static double caclulate_file_entropy(char *file_location);
static int search_conf_for_pass(File_Info *fi, All_Results *ar, Args *cmdline);

/* ============================ FUNCTIONS ============================== */

/**
 * Performs all of the intersesting file scans on a given file 
 * @param fi A struct containing the files information 
 * @param ar a struct containing all of the results that enumy has previously found
 * @param cmdline A struct containing the runtime arguments for enumy 
 * @return the number of findings that the scan found
 */
int intresting_files_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;
    findings += extension_checker(fi, ar, cmdline);
    findings += file_name_checker(fi, ar, cmdline);
    return findings;
}

/* ============================ STATIC FUNCTIONS ============================== */

/**
 * This scan kicks off other scans based of the files extension 
 * @param fi A struct containing the files information 
 * @param ar a struct containing all of the results that enumy has previously found
 * @param cmdline A struct containing the runtime arguments for enumy 
 * @param the number of findings that the scan found
 */
static int extension_checker(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;

    switch (fi->extension[0])
    {
    case 'a':
        if (strcmp(fi->extension, "aes") == 0)
            findings += (check_for_encryption_key(fi, ar, cmdline) == true) ? 1 : 0;
        break;
    case 'b':
        if (strcmp(fi->extension, "bk") == 0)
        {
            add_issue(INFO, 46, fi->location, ar, cmdline, "Found possible backup file", "");
            return 1;
        }
        break;
    case 'c':
        if ((strcmp(fi->extension, "config") == 0) ||
            (strcmp(fi->extension, "conf") == 0))
            findings += search_conf_for_pass(fi, ar, cmdline);

        else if (strcmp(fi->extension, "conf") == 0)
            findings += search_conf_for_pass(fi, ar, cmdline);
        break;
    case 'd':
        if (strcmp(fi->extension, "des") == 0)
            findings += (check_for_encryption_key(fi, ar, cmdline) == true) ? 1 : 0;

        break;
    case 'k':
        if (strcmp(fi->extension, "key") == 0)
            findings += (check_for_encryption_key(fi, ar, cmdline) == true) ? 1 : 0;
        break;
    case 'p':
        if (strcmp(fi->extension, "php") == 0)
            findings += (search_conf_for_pass(fi, ar, cmdline) == true) ? 1 : 0;

        else if (
            (strcmp(fi->extension, "password") == 0) ||
            (strcmp(fi->extension, "passwords") == 0) ||
            (strcmp(fi->extension, "private") == 0) ||
            (strcmp(fi->extension, "pk") == 0))
            findings += (check_for_encryption_key(fi, ar, cmdline) == true) ? 1 : 0;
        break;
    case 'r':
        if (strcmp(fi->extension, "rsa") == 0)
            findings += (check_for_encryption_key(fi, ar, cmdline) == true) ? 1 : 0;

        break;
    case 's':
        if (strcmp(fi->extension, "secret") == 0)
            findings += (check_for_encryption_key(fi, ar, cmdline) == true) ? 1 : 0;

        else if (strcmp(fi->extension, "so") == 0)
            findings += check_for_writable_shared_object(fi, ar, cmdline);

        break;
    }
    return findings;
}

/**
 * Checks to see if the current file has a certain name. If the file does then this 
 * function will kick of the relevant scans for the current file 
 * @param fi A struct containing the files information 
 * @param ar a struct containing all of the results that enumy has previously found
 * @param cmdline A struct containing the runtime arguments for enumy 
 * @return the number of findings that the scan found
 */
static int file_name_checker(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;
    switch (fi->name[0])
    {
    case 'c':
        if (strcasestr(fi->name, "core") != NULL)
            findings += core_dump_scan(fi, ar, cmdline);
        break;
    case 'i':
        if (strcasestr(fi->name, "id_rsa") != NULL && strcmp(fi->extension, "pub") != 0)
        {
            if (check_for_encryption_key(fi, ar, cmdline))
                findings++;
            break;
        }
        if (strcasestr(fi->name, "id_dsa") != NULL && strcmp(fi->extension, "pub") != 0)
        {
            if (check_for_encryption_key(fi, ar, cmdline))
                findings++;
            break;
        }
        break;
    }
    return findings;
}

/**
 * Only call with files that could contain encryption keys 
 * returns false if the file is part of a test directory
 * If the file has low entropy then report this as an encryption key if the permissions 
 * of this file is too loose 
 * @param fi A struct containing the files information 
 * @param ar a struct containing all of the results that enumy has previously found
 * @param cmdline A struct containing the runtime arguments for enumy 
 * @return true if the file is thought to contain an encryption key 
 */
static bool check_for_encryption_key(File_Info *fi, All_Results *ar, Args *cmdline)
{
    float entropy;

    /* Ignore files in test as they give too many false positives */
    if (strstr(fi->location, "test") ||
        strstr(fi->location, "integration"))
        return false;

    /* Data probably too big to be a key */
    if (fi->stat->st_size > 100000 || fi->stat->st_size < 100)
        return false;

    /* Cannot read the file */
    if (access(fi->location, R_OK) != 0)
    {
    NONREADABLE:
        add_issue(INFO, 46, fi->location, ar, cmdline, "None readable potential encryption key", "");
        return true;
    }

    /* Check the file's entropy */
    entropy = caclulate_file_entropy(fi->location);
    if (entropy > 7.0)
        return false;

    if (entropy == -1)
        DEBUG_PRINT("Failed to calculate entropy for file at location -> %s\n", fi->location);

    if (getuid() == 0 && fi->stat->st_uid == 0)
        goto NONREADABLE;

    /* Raise the issue */
    add_issue(HIGH, 45, fi->location, ar, cmdline, "Low entropy file that could be a private key", "");
    return true;
}

/**
 * This function is used to try and determine if a file such as x.rsa is the key
 * or the file is encrypted data. Key's should have low entropy and good encryption
 * should be indistingushable from random data. Note that this only works if the key encoded
 * @param fi A struct containing the files information 
 * @param ar a struct containing all of the results that enumy has previously found
 * @param cmdline A struct containing the runtime arguments for enumy 
 * @return the files entropy or -1 if entropy calculations failed
 */
static double caclulate_file_entropy(char *file_location)
{
    char str[ENTROPY_SIZE];
    unsigned char current_pos;
    unsigned int len, *hist, histlen, i;
    int current_fget;
    FILE *f;
    int wherechar[256];
    double entropy = 0;

    /* Open the file */
    f = fopen(file_location, "r");
    if (f == NULL)
    {
        DEBUG_PRINT("Failed to open file at location (Entropy) -> %s\n", file_location);
        return -1;
    }

    for (len = 0; !feof(f) && len < ENTROPY_SIZE; len++)
    {
        current_fget = fgetc(f);
        if (current_fget == EOF)
            break;
        str[len] = (unsigned char)current_fget;
    }

    fclose(f);

    /* Check for integer underflow */
    if (len == 0)
        str[0] = '\0';
    else
        str[--len] = '\0';

    /* Allocate the histogram */
    hist = (unsigned int *)calloc(len, sizeof(int));
    if (hist == NULL)
    {
        DEBUG_PRINT("Failed to allocate %li bytes during calloc entropy -> %s\n", (long int)len * sizeof(long int), file_location);
        return -1;
    }

    /* init histogram */
    histlen = 0;
    for (i = 0; i < 256; i++)
        wherechar[i] = 0;

    /* Populate the histogram */
    for (i = 0; i < len; i++)
    {
        current_pos = str[i];
        if (wherechar[(int)current_pos] == 0)
        {
            wherechar[current_pos] = histlen;
            histlen++;
        }
        hist[wherechar[(unsigned char)str[i]]]++;
    }

    /* Calculate entropy */
    for (i = 0; i < histlen; i++)
        entropy -= (double)hist[i] / len * log2((double)hist[i] / len);

    if (hist != NULL)
        free(hist);

    return entropy;
}

/**
 * Only call if the file is a config file 
 * loops through all of the lines in the config file and checks to see if the file 
 * contains any references to passwords
 * @param fi A struct containing the files information 
 * @param ar a struct containing all of the results that enumy has previously found
 * @param cmdline A struct containing the runtime arguments for enumy j
 * @return 1 if found any references to passwords else 0
 */
static int search_conf_for_pass(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;
    char line[MAXSIZE];
    FILE *file = fopen(fi->location, "r");

    /* Check the file is not NULL */
    if (file == NULL)
    {
        DEBUG_PRINT("Failed to open file at location -> %s\n", fi->location);
        return findings;
    }

    /* Search for password keywords and raise issue if found */
    while (fgets(line, MAXSIZE, file))
    {
        /* Ignore commented lines */
        if (line[0] == '#')
            continue;

        if (
            (strcasestr(line, "password=") != NULL) ||
            (strcasestr(line, "passwd") != NULL) ||
            (strcasestr(line, "private_key") != NULL) ||
            (strcasestr(line, "privatekey") != NULL) ||
            (strcasestr(line, "private-key") != NULL))
        {
            add_issue(INFO, 47, fi->location, ar, cmdline, "Config file could contain passwords", "");
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}

/**
 * Checks to see if the current file is writable only call if the file is a shared 
 * object 
 * @param fi A struct containing the files information 
 * @param ar a struct containing all of the results that enumy has previously found
 * @param cmdline A struct containing the runtime arguments for enumy 
 * @return 1 if found to be writable 
 */
static int check_for_writable_shared_object(File_Info *fi, All_Results *ar, Args *cmdline)
{
    if (has_global_write(fi))
    {
        add_issue(HIGH, 48, fi->location, ar, cmdline, "World Writable shared object found", "");
        return 1;
    }
    return 0;
}