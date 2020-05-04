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
#include "gui.h"
#include "scan.h"
#include "results.h"
#include "debug.h"

#define KEY_J 106
#define KEY_K 107
#define KEY_SHOW_HIGH 104
#define KEY_SHOW_MEDIUM 109
#define KEY_SHOW_LOW 108
#define KEY_SHOW_INFO 105
#define KEY_DEL_CURRENT 100
#define KEY_DEL_ALL_ID 68
#define KEY_QUIT 113

bool DEBUG = false;

typedef struct UserInputThreadArgs
{
    Ncurses_Layout *layout;
    All_Results *all_results;
} UserInputThreadArgs;

void sigint_handler(int sig)
{
    if (sig == SIGINT)
    {
        endwin();
        exit(0);
    }
}

void banner()
{
    puts(" ▄█▀─▄▄▄▄▄▄▄─▀█▄  _____  				 ");
    puts(" ▀█████████████▀ |   __|___ _ _ _____ _ _ ");
    puts("     █▄███▄█     |   __|   | | |     | | |");
    puts("      █████      |_____|_|_|___|_|_|_|_  |");
    puts("      █▀█▀█                          |___|");
    puts("");
    puts(" https://github.com/luke-goddard/enumy");
}

void help()
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
    puts(" -d           Debug mode");
    puts(" -n           Enabled ncurses");
    puts(" -h           Show help");
    exit(0);
}

void *handle_user_input(void *user_input_args)
{
    UserInputThreadArgs *args = (UserInputThreadArgs *)user_input_args;
    All_Results *all_results = args->all_results;
    Ncurses_Layout *layout = args->layout;
    char input;

    while ((input = getch()) != KEY_QUIT)
    {
        switch (input)
        {
        case KEY_J:
            layout->cursor_position++;
            break;

        case KEY_K:
            layout->cursor_position--;
            break;

        case KEY_SHOW_HIGH:
            layout->current_category = HIGH;
            update_table(all_results, layout);
            update_bars(all_results, layout);
            break;

        case KEY_SHOW_MEDIUM:
            layout->current_category = MEDIUM;
            update_table(all_results, layout);
            update_bars(all_results, layout);
            break;

        case KEY_SHOW_LOW:
            layout->current_category = LOW;
            update_table(all_results, layout);
            update_bars(all_results, layout);
            break;

        case KEY_SHOW_INFO:
            layout->current_category = INFO;
            update_table(all_results, layout);
            update_bars(all_results, layout);
            break;
        }
    }
    kill(getpid(), SIGINT);
    return NULL;
}

void show_runtime_args(Args *args)
{
    printf("Save Location   -> %s\n", args->save_location);
    printf("Ignore Dir      -> %s\n", args->ignore_scan_dir);
    printf("Walk Dir        -> %s\n", args->walk_dir);
    printf("Full Scan       -> %s\n", args->enabled_full_scans ? "true" : "false");
    printf("Ncurses         -> %s\n", args->enabled_ncurses ? "true" : "false");
    printf("Missing *.so    -> %s\n", args->enabled_missing_so ? "true" : "false");
    printf("Threads         -> %i\n", args->fs_threads);
}

int main(int argc, char *argv[])
{
    int opt;
    int userinput_threads = 0;

    struct Args *args = (struct Args *)malloc(sizeof(struct Args));
    strncpy(args->save_location, "enumy.json", sizeof(args->save_location) - 1);
    args->ignore_scan_dir[0] = '\0';
    args->walk_dir[0] = '/';
    args->enabled_full_scans = false;
    args->enabled_ncurses = false;
    args->enabled_missing_so = false;
    args->fs_threads = 4;

    DEBUG = false;
    struct Ncurses_Layout nlayout = {
        .logo = NULL,
        .bars = NULL,
        .main = NULL,
        .id = NULL};

    All_Results *all_results = initilize_total_results();

    struct UserInputThreadArgs user_input_thread_args = {
        .layout = &nlayout,
        .all_results = all_results};

    signal(SIGINT, sigint_handler);

    while ((opt = getopt(argc, argv, "sdfhno:i:w:t:")) != -1)
    {
        switch (opt)
        {
        case 'h': // help
            banner();
            help();
            break;

        case 'f':
            args->enabled_full_scans = true;
            break;

        case 'o':
            strncpy(args->save_location, optarg, MAXSIZE);
            break;

        case 'i':
            strncpy(args->ignore_scan_dir, optarg, MAXSIZE);
            break;

        case 'w':
            strncpy(args->walk_dir, optarg, MAXSIZE);
            break;

        case 't':
            userinput_threads = atoi(optarg);
            if (userinput_threads == 0)
            {
                banner();
                printf("\nPlease enter a valid thread number\n");
                exit(EXIT_FAILURE);
            }
            args->fs_threads = userinput_threads;
            break;

        case 'n':
            args->enabled_ncurses = true;
            break;

        case 'd':
            DEBUG = true;
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

    if (args->enabled_ncurses == true)
    {
        char *_;
        pthread_t user_input_thread;
        init_ncurses_layout(&nlayout, all_results);
        pthread_create(&user_input_thread, NULL, &handle_user_input, &user_input_thread_args);
        args->enabled_ncurses = true;
        start_scan(&nlayout, all_results, args);
        pthread_join(user_input_thread, (void **)&_);
        endwin();
        free(args);
        return 0;
    }
    else
    {
        banner();
        printf("\n\n");
        if (DEBUG)
        {
            show_runtime_args(args);
        }
        start_scan(&nlayout, all_results, args);
    }
    free(args);
    return 0;
}
