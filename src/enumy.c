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

/* ============================ GLOBAL VARS ============================== */

/* ============================ TODO ============================== */
/* Change the global variables naming scheme */
/* ============================ TODO ============================== */

bool Debug = false;
bool DebugExtra = false;
bool AuditModeEnabled = false;

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

    All_Results *all_results = initilize_total_results();

    while ((opt = getopt(argc, argv, "ad:fhno:i:w:t:p:g:")) != -1)
    {
        switch (opt)
        {
        /* Help */
        case 'h':
            banner();
            help();
            break;

        /* Log issues to screen that would not help in a CTF */
        case 'a':
            AuditModeEnabled = true;
            break;

        /* Enable full scan */
        case 'f':
            args->enabled_full_scans = true;
            break;

        /* Output location */
        case 'o':
            strncpy(args->save_location, optarg, MAXSIZE - 1);
            break;

        /* Ignore directory */
        case 'i':
            strncpy(args->ignore_scan_dir, optarg, MAXSIZE - 1);
            break;

        /* Walk directory */
        case 'w':
            strncpy(args->walk_dir, optarg, MAXSIZE - 1);
            break;

        /* Threads */
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

        /* Debug level */
        case 'd':
            Debug = true;
            if (atoi(optarg) == 2)
                DebugExtra = true;
            break;

        /* Print level */
        case 'p':
            if (!set_disable_print_level(optarg))
            {
                banner();
                printf("-p requires one or more of the following characters: h m l i\n");
                printf("Where h=High, m=Medium, l=Low, i=Info\n");
                exit(EXIT_FAILURE);
            }
            break;

        /* Print level greater than */
        case 'g':
            if (!set_print_lvl_greater_than(optarg))
            {
                banner();
                printf("-p requires one of the following characters: h m l\n");
                printf("Where h=High, m=Medium, l=Low\n");
                exit(EXIT_FAILURE);
            }
            break;

        default:
            banner();
            help();
            break;
        }
    }

    banner();
    printf("\n\n");

    if (Debug)
        show_runtime_args(args);

    /* Make sure that we scan scave our results */
    FILE *fptr = fopen(args->save_location, "w");
    if (fptr == NULL)
    {
        printf("Failed to open %s\n", args->save_location);
        exit(EXIT_FAILURE);
    }

    fclose(fptr);
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
    puts(" Enumy - Used to enumerate the target the target environment & look for");
    puts(" common security vulnerabilities and hostspots");
    puts(" ----------------------------------------------------------------------");
    puts("");
    puts(" Output");
    puts("  -o <loc>     OUTPUT results to location (default enumy.json)");
    puts("");
    puts(" Walking Filesystem");
    puts("  -i <loc>     IGNORE files in this directory (usefull for network shares)");
    puts("  -w <loc>     Only WALK files in this directory (usefull for devlopment)");
    puts("");
    puts(" Scan Options");
    puts("  -f           run FULL scans (CPU intensive scan's enabled)");
    puts("  -t <num>     THREADS (default 4)");
    puts("");
    puts(" Printing Options");
    puts("  -a           Print all security AUDIT issues to screen (probably won't help duing a CTF)");
    puts("               Issues are ALWAYS logged in result files regardless of this flag being set.");
    puts("  -d <1|2>     Print DEBUG mode (1 low, 2 high) to enable errors being printed to screen.");
    puts("  -g <H|M|L>   print to screen values GREATER than or equal to high, medium & low");
    puts("  -p <H|M|L|I> do not PRINT to screen high, medium, low & info issues (see below for example)");
    puts("  -m 1-100     MAXIMUM number of issues with same name to print to screen default (unlimited)");
    puts("");
    puts(" Other Options");
    puts("  -h           Show HELP");
    puts("");
    puts(" Example:");
    puts("   ./enumy");
    puts("   Run enumy with default configuritaions this will be adequate for CTFs");
    puts("");
    puts(" Example:");
    puts("   ./enumy -i /mnt/smb/ -f -t 12 -g l");
    puts("   Ignoring files in /mnt/smb/, run a full scan with 12 threads printing");
    puts("   HIGH, MED and LOW findings");
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