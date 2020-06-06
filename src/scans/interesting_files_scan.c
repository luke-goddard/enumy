/*
    The job of this file is to try and identify files that could be 
    of intrest to an attacker without showing too many false positives
    Examples of these files are backupfiles, private keys, certificates,
    writable config files and coredump files. 
*/

#define _GNU_SOURCE

#include "main.h"
#include "results.h"
#include "file_system.h"
#include "error_logger.h"
#include "elf_parsing.h"
#include "debug.h"

#include <sys/types.h>
#include <errno.h>
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

int intresting_files_scan(File_Info *fi, All_Results *ar);

static int extension_checker(File_Info *fi, All_Results *ar);
static int file_name_checker(File_Info *fi, All_Results *ar);
static bool check_for_encryption_key(File_Info *fi, All_Results *ar);
static int check_for_writable_shared_object(File_Info *fi, All_Results *ar);
static double caclulate_file_entropy(All_Results *ar, char *file_location);
static int search_conf_for_pass(File_Info *fi, All_Results *ar);
static int test_if_encryption_key(File_Info *fi, All_Results *ar);
static int test_if_config_file(File_Info *fi, All_Results *ar);

/* ============================ GLOBAL VARS ============================== */

/* Files that could contain passwords */
char *ConfigExtensions[] = {
    "php", "ini", "conf", "config", "configuration"};

/* Files that could contain private keys */
char *EncryptionKeyWords[] = {
    "password", "passwords", "key", "id_dsa", "id_ecdsa", "id_rsa", "rsa", "des",
    "pk", "secret", "dsa", "ecdsa", "private", "privatekey", "private-key"};

int EncryptionKeyWordsSize = (sizeof(EncryptionKeyWords) / sizeof(EncryptionKeyWords[0]));
int ConfigExtensionsSize = (sizeof(ConfigExtensions) / sizeof(ConfigExtensions[0]));

/* ============================ FUNCTIONS ============================== */

/**
 * This is more a generic scan that tries to clasify the current file based of trivial things 
 * like file extensions and the contents of this file. The scan will look for config files containing 
 * passwords, encryption keys, backup files etc. 
 * @param fi This is the current file that's going to be scanned 
 * @param ar This is the structure that holds the link lists with the results 
 */
int intresting_files_scan(File_Info *fi, All_Results *ar)
{
    int findings = 0;

    findings += test_if_encryption_key(fi, ar);
    findings += test_if_config_file(fi, ar);
    findings += extension_checker(fi, ar);
    findings += file_name_checker(fi, ar);
    return findings;
}

/* ============================ STATIC FUNCTIONS ============================== */

/**
 * This scan kicks off other scans based of the files extension 
 * @param fi A struct containing the files information 
 * @param ar a struct containing all of the results that enumy has previously found
 */
static int extension_checker(File_Info *fi, All_Results *ar)
{
    int findings = 0;

    switch (fi->extension[0])
    {
    case 'b':
        if ((strcmp(fi->extension, "bk") == 0) || (strcmp(fi->extension, "bak") == 0) || strcmp(fi->extension, "old") == 0)
            add_issue(INFO, AUDIT, fi->location, ar, "Found possible backup file", "Worth checking if there is anything sensative inside");
        break;
    case 'o':
        if ((strcmp(fi->extension, "ovpn") == 0))
        {
            if (has_global_read(fi))
                add_issue(HIGH, CTF, fi->location, ar, "Found readable VPN credentials", "");
            else
                add_issue(INFO, CTF, fi->location, ar, "Found non readable VPN credentials", "");
        }
        break;
    case 'l':
        if ((strcmp(fi->extension, "log") == 0) && has_global_write(fi))
            add_issue(MEDIUM, AUDIT, fi->location, ar, "Found a writeable log file", "");
        break;

    case 's':
        if (strcmp(fi->extension, "so") == 0)
            findings += check_for_writable_shared_object(fi, ar);
        break;
    }
    return findings;
}

/**
 * This function will check to see if the file is an encryption key
 * Based of the files name and extension 
 * @param fi The file's information 
 * @param ar The results struct
 */
static int test_if_encryption_key(File_Info *fi, All_Results *ar)
{
    for (int i = 0; i < EncryptionKeyWordsSize; i++)
    {
        if (
            (strcmp(fi->extension, EncryptionKeyWords[i]) == 0) ||
            (strcmp(fi->name, EncryptionKeyWords[i]) == 0))
        {

            return check_for_encryption_key(fi, ar);
        }
    }
    return 0;
}

/**
 * This function will check to see if the file is an configuration file 
 * Based of the files name and extension 
 * @param fi The file's information 
 * @param ar The results struct
 */
static int test_if_config_file(File_Info *fi, All_Results *ar)
{
    for (int i = 0; i < ConfigExtensionsSize; i++)
    {
        if (strcmp(fi->extension, ConfigExtensions[i]) == 0)
            return search_conf_for_pass(fi, ar);
    }
    return 0;
}

/**
 * Checks to see if the current file has a certain name. If the file does then this 
 * function will kick of the relevant scans for the current file 
 * @param fi A struct containing the files information 
 * @param ar a struct containing all of the results that enumy has previously found
 * @return the number of findings that the scan found
 */
static int file_name_checker(File_Info *fi, All_Results *ar)
{
    int findings = 0;
    switch (fi->name[0])
    {
    case 'c':
        /* Core dump files */
        if (strcasestr(fi->name, "core") != NULL)
            findings += core_dump_scan(fi, ar);
        break;

    case 'p':
        if ((strcmp(fi->name, "passwd.bak") == 0) || strcmp(fi->name, "passwd-") == 0)
            add_issue(INFO, CTF, fi->location, ar, "Found backup /etc/passwd file", "");
        break;

    case 's':
        if ((strcmp(fi->name, "shadow.bak") == 0) || strcmp(fi->name, "shadow-") == 0)
            add_issue(MEDIUM, CTF, fi->location, ar, "Found backup /etc/shadow file", "");
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
 * @return true if the file is thought to contain an encryption key 
 */
static bool check_for_encryption_key(File_Info *fi, All_Results *ar)
{
    float entropy;

    /* Data probably too big to be a key */
    if (fi->stat->st_size > 100000 || fi->stat->st_size < 100)
        return false;

    /* Cannot read the file */
    if (access(fi->location, R_OK) != 0)
    {
    NONREADABLE:
        add_issue(INFO, CTF, fi->location, ar, "None readable potential encryption key", "Private keys should never be readable");
        return true;
    }

    /* Check the file's entropy */
    entropy = caclulate_file_entropy(ar, fi->location);
    if (entropy > 7.0)
        return false;

    if (entropy == -1)
    {
        log_warn_loc(ar, "Entropy calculation returned a bad value", fi->location);
        return false;
    }

    if (getuid() == 0 && fi->stat->st_uid == 0)
        goto NONREADABLE;

    /* Raise the issue */
    add_issue(HIGH, CTF, fi->location, ar, "Low entropy file that could be a private key", "");
    return true;
}

/**
 * This function is used to try and determine if a file such as x.rsa is the key
 * or the file is encrypted data. Key's should have low entropy and good encryption
 * should be indistingushable from random data. Note that this only works if the key encoded
 * @param file_location location of the file to calculate entropy for 
 * @return the files entropy or -1 if entropy calculations failed
 */
static double caclulate_file_entropy(All_Results *ar, char *file_location)
{
    char str[ENTROPY_SIZE];
    unsigned int len, *hist, histlen, i;
    FILE *f;
    int wherechar[256];
    double entropy = 0;

    /* Open the file */
    f = fopen(file_location, "r");
    if (f == NULL)
    {
        log_warn_errno_loc(ar, "Failed to calulate entropy", file_location, errno);
        return -1;
    }

    for (len = 0; !feof(f) && len < ENTROPY_SIZE; len++)
    {
        int current_fget = fgetc(f);
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
        log_error_errno_loc(ar, "Failed to calculate entropy due to calloc", file_location, errno);
        return -1;
    }

    /* init histogram */
    histlen = 0;
    for (i = 0; i < 256; i++)
        wherechar[i] = 0;

    /* Populate the histogram */
    for (i = 0; i < len; i++)
    {
        unsigned char current_pos = str[i];
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
 * @return 1 if found any references to passwords else 0
 */
static int search_conf_for_pass(File_Info *fi, All_Results *ar)
{
    int findings = 0;
    char line[MAXSIZE];
    FILE *file = fopen(fi->location, "r");

    /* Check the file is not NULL */
    if (file == NULL)
    {
        log_warn_errno_loc(ar, "Failed to open config file", fi->location, errno);
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
            add_issue(INFO, CTF, fi->location, ar, "Config file could contain passwords", "This scans searches for key words and produces many false positives");
            findings++;
        }
    }
    fclose(file);
    return findings;
}

/**
 * Checks to see if the current file is writable only call if the file is a shared 
 * object 
 * @param fi A struct containing the files information 
 * @param ar a struct containing all of the results that enumy has previously found
 * @return 1 if found to be writable 
 */
static int check_for_writable_shared_object(File_Info *fi, All_Results *ar)
{
    if (has_global_write(fi))
    {
        add_issue(HIGH, CTF, fi->location, ar, "World Writable shared object found", "Is there any files on the system that use these shared objects?");
        return 1;
    }
    return 0;
}