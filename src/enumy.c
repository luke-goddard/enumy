/*
    This is the entry point for the program it's job is to parse command line 
    output and spawn the relevant threads. 
*/
#include <getopt.h>
#include <locale.h>
#include <unistd.h>
#include <ncurses.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>

#include "main.h"
#include "scan.h"
#include "results.h"
#include "debug.h"

/* ============================ DEFINES ============================== */

#define KEY_J 106
#define KEY_K 107
#define KEY_SHOW_HIGH 104
#define KEY_SHOW_MEDIUM 109
#define KEY_SHOW_LOW 108
#define KEY_SHOW_INFO 105
#define KEY_DEL_CURRENT 100
#define KEY_DEL_ALL_ID 68
#define KEY_QUIT 113

/* ============================ GLOBAL VARS ============================== */

/* ============================ TODO ============================== */
/* Change the global variables naming scheme */
/* ============================ TODO ============================== */

bool DEBUG = false;
bool DEBUG_EXTRA = false;

/* ============================ PROTOTYPES ============================== */

static void show_runtime_args(Args *args);
static void banner();
static void help();

/* ============================ FUNCTIONS ============================== */

int main(int argc, char *argv[])
{
    int opt;
    int userinput_threads = 0;

    struct Args *args = (struct Args *)malloc(sizeof(struct Args));

    if (args == NULL)
    {
        printf("Failed to allocate memory for arguments\n");
        exit(1);
    }

    memset(args->save_location, '\0', sizeof(args->save_location));
    memset(args->ignore_scan_dir, '\0', sizeof(args->ignore_scan_dir));
    memset(args->walk_dir, '\0', sizeof(args->walk_dir));

    args->walk_dir[0] = '/';
    args->enabled_full_scans = false;
    args->enabled_ncurses = false;
    args->enabled_missing_so = false;
    args->fs_threads = 4;

    strncpy(args->save_location, "enumy.json", sizeof(args->save_location) - 1);

    DEBUG = false;

    All_Results *all_results = initilize_total_results();

    while ((opt = getopt(argc, argv, "sd:fhno:i:w:t:")) != -1)
    {
        switch (opt)
        {
        case 'h':
            banner();
            help();
            break;

        case 'f':
            args->enabled_full_scans = true;
            break;

        case 'o':
            strncpy(args->save_location, optarg, MAXSIZE - 1);
            break;

        case 'i':
            strncpy(args->ignore_scan_dir, optarg, MAXSIZE - 1);
            break;

        case 'w':
            strncpy(args->walk_dir, optarg, MAXSIZE - 1);
            break;

        case 't':
            userinput_threads = atoi(optarg);
            if ((userinput_threads < 1) || (userinput_threads > 64))
            {
                banner();
                printf("\nPlease enter a valid thread number\n");
                exit(EXIT_FAILURE);
            }
            args->fs_threads = userinput_threads;
            break;

        case 'd':
            DEBUG = true;
            if (atoi(optarg) == 2)
                DEBUG_EXTRA = true;
            break;

        case 's':
            args->enabled_missing_so = true;
            break;

        default:
            banner();
            help();
            break;
        }
    }

    banner();
    printf("\n\n");

    if (DEBUG)
        show_runtime_args(args);

    start_scan(all_results, args);

    free(args);
    free_total_results(all_results);

    return 0;
}

/* ============================ STATIC FUNCTIONS ============================== */

static void banner()
{
    puts(" ▄█▀─▄▄▄▄▄▄▄─▀█▄  _____  				 ");
    puts(" ▀█████████████▀ |   __|___ _ _ _____ _ _ ");
    puts("     █▄███▄█     |   __|   | | |     | | |");
    puts("      █████      |_____|_|_|___|_|_|_|_  |");
    puts("      █▀█▀█                          |___|");
    puts("");
    puts(" https://github.com/luke-goddard/enumy");
}

static void help()
{
    puts("");
    puts("------------------------------------------");
    puts("");
    puts("Enumy - Used to enumerate the target");
    puts("the target environment and look for common");
    puts("security vulnerabilities and hostspots");
    puts("");
    puts(" -o <loc>     Save results to location");
    puts(" -i <loc>     Ignore files in this directory (usefull for network shares)");
    puts(" -w <loc>     Only walk files in this directory (usefull for devlopment)");
    puts(" -t <num>     Threads (default 4)");
    puts(" -f           Run full scans");
    puts(" -s           Show missing shared libaries");
    puts(" -d <1|2>     Debug mode (1 low, 2 high)");
    puts(" -h           Show help");
    exit(0);
}

static void show_runtime_args(Args *args)
{
    printf("Save Location   -> %s\n", args->save_location);
    printf("Ignore Dir      -> %s\n", args->ignore_scan_dir);
    printf("Walk Dir        -> %s\n", args->walk_dir);
    printf("Full Scan       -> %s\n", args->enabled_full_scans ? "true" : "false");
    printf("Missing *.so    -> %s\n", args->enabled_missing_so ? "true" : "false");
    printf("Threads         -> %i\n", args->fs_threads);
}