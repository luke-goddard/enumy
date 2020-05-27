/*
    CHANGE ME 
*/

#pragma once

#include "main.h"

#include <stdbool.h>
#include <pthread.h>

/* ============================ DEFINES ============================== */

#define COLOR_HIGH "\033[0;31m"   // red
#define COLOR_MEDIUM "\033[0;33m" // yellow
#define COLOR_LOW "\033[0;36m"    // blue
#define COLOR_INFO "\033[0;32m"   // green
#define COLOR_BOLD "\033[0;1m"
#define COLOR_ULINE "\033[0;4m"
#define COLOR_RESET "\033[0;m"

#define HIGH 3
#define MEDIUM 2
#define LOW 1
#define INFO 0
#define NOT_FOUND 99
#define NO_REFRESH -1

#define FIRST_ID -1
#define INCOMPLETE_ID -1

/* ============================ STRUCTS ============================== */

typedef struct Result
{
    int issue_id;
    char issue_name[MAXSIZE];
    char description[MAXSIZE];
    char location[MAXSIZE];
    char other_info[MAXSIZE];
    bool no_ls;
    struct Result *previous, *next;
} Result;

typedef struct All_Results
{
    Result *high;
    Result *high_end_node;
    int high_tot;

    Result *medium;
    Result *medium_end_node;
    int medium_tot;

    Result *low;
    Result *low_end_node;
    int low_tot;

    Result *info;
    Result *info_end_node;
    int info_tot;

    int gui_requires_refresh;
    int highest_id;
    pthread_mutex_t mutex;
} All_Results;

/* ============================ PROTOTYPES ============================== */

void print_heading(char *s);
void print_heading_oneliner(char *s);

All_Results *initilize_total_results();
void free_total_results(All_Results *ar);

void add_issue(int severity, int id, char *location, All_Results *ar, Args *cmdline, char *name, char *other);
Result *create_new_issue();
void set_id(int issue_id, Result *result_node);
void set_id_and_desc(int issue_id, Result *result_node);
void set_issue_name(char *issue_name, Result *result_node);
void set_issue_description(char *issue_description, Result *result_node);
void set_issue_location(char *issue_location, Result *result_node);
void set_other_info(char *issue_location, Result *result_nodee);
void set_no_ls(Result *result_node);

bool add_new_result_high(Result *new_result, All_Results *result, Args *cmdline);
bool add_new_result_medium(Result *new_result, All_Results *result, Args *cmdline);
bool add_new_result_low(Result *new_result, All_Results *result, Args *cmdline);
bool add_new_result_info(Result *new_result, All_Results *result, Args *cmdline);

Result *get_result_high(All_Results *ar, int index);
Result *get_result_medium(All_Results *ar, int index);
Result *get_result_low(All_Results *ar, int index);
Result *get_result_info(All_Results *ar, int index);

void print_all_results(All_Results *all_results);
void print_high_results(All_Results *all_results);
void print_medium_results(All_Results *all_results);
void print_low_results(All_Results *all_results);
void print_info_results(All_Results *all_results);

int get_results_total(All_Results *result);
int get_tot_high(All_Results *result);
int get_tot_medium(All_Results *result);
int get_tot_low(All_Results *result);
int get_tot_info(All_Results *result);

int get_all_issues_with_id(All_Results *ar, Vector *v, int id);