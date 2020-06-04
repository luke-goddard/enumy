/*
    This header file exposes all the functionality that relates to storing 
    and fetching results found from running scans.

    The All_Results struct is used exensivly throughout enumy and is where 
    all the results are stored. The All_Results struct contains pointers 
    to linked lists where each linked list is grouped together by the severity
    of the issue found. The following severities exist. 

    High    - Important finding
    Medium  - Could be important 
    Low     - Generally something that bad practice but not a major threat
    Info    - Useful information, security hotspot etc 

    All operations should be thread safe
*/

#pragma once

#include "main.h"

#include <stdbool.h>
#include <pthread.h>

/* ============================ DEFINES ============================== */

#define HIGH 3   /* HIGH issue code */
#define MEDIUM 2 /* MEDIUM issue code */
#define LOW 1    /* LOW issue code */
#define INFO 0   /* INFO issue code */

#define CTF 0   /* Only display issues that would be useful during a CTF */
#define AUDIT 1 /* Dispaly all issues, even those that would not be useful in a CTF */

#define COLOR_HIGH "\033[0;31m"   /* RED */
#define COLOR_MEDIUM "\033[0;33m" /* YELLOW */
#define COLOR_LOW "\033[0;36m"    /* BLUE */
#define COLOR_INFO "\033[0;32m"   /* GREEN */
#define COLOR_BOLD "\033[0;1m"    /* Makes font bold */
#define COLOR_ULINE "\033[0;4m"   /* Underlines the font */
#define COLOR_DIM "\033[0;2m"     /* Dim colour code */
#define COLOR_RESET "\033[0;m"    /* Resets the above attributes */

#define NOT_FOUND 999999 /* Used to signify that the result is not found */
#define FIRST_ID 1       /* Used to initilize the linked lists */
#define INCOMPLETE_ID 0  /* Used to initilize the linked lists */

/* ============================ STRUCTS ============================== */

/* This struct contains all the information needed to store a result node in the linked list */
typedef struct Result
{
    unsigned long issue_id;         /* Each issue type should have a uniq id */
    char issue_name[MAXSIZE];       /* Each issue should have name that corisponds to the id */
    char location[MAXSIZE];         /* Each issue should have a location attached to it */
    char other_info[MAXSIZE];       /* Optional other infomation that can be attached to it */
    bool no_ls;                     /* Optional bool to disable ls -ltra print message */
    struct Result *previous, *next; /* Pointer to the next and previous result in the linked list */
} Result;

/* This struct holds all the issues found by enumy at run time */
typedef struct All_Results
{
    Result *high;                /* Linked list to all HIGH issues */
    Result *high_end_node;       /* Last element in the HIGH linked list */
    int high_tot;                /* Total number of nodes in the HIGH linked list */
    vec_unsigned_long *high_ids; /* Vector containing all the unique high id numbers */

    Result *medium;                /* Linked list to all the MEDIUM issues */
    Result *medium_end_node;       /* Last element in the MEDIUM linked list */
    int medium_tot;                /* Total number of nodes in the MEDIUM linked list */
    vec_unsigned_long *medium_ids; /* Vector containing all the unique medium id numbers */

    Result *low;                /* Linked list to all the LOW issues */
    Result *low_end_node;       /* Last element in the LOW linked list */
    int low_tot;                /* Total number of nodes in the LOW linked list */
    vec_unsigned_long *low_ids; /* Vector containing all the unique low id numbers */

    Result *info;                /* Linked list to all the INFO issues */
    Result *info_end_node;       /* Last element in the INFO linked list */
    int info_tot;                /* Total number of nodes in the INFO linked list */
    vec_unsigned_long *info_ids; /* Vector containing all the unique info id numbers */

    vec_str_t *errors;   /* We can record errors for the reporter to log */
    vec_str_t *warnings; /* We can record warnings for the reporter to log */

    int issues_not_logged_to_screen; /* Number of issues in the struct that were not printed to stdout */

    pthread_mutex_t mutex; /* Makes the structure thread safe */
} All_Results;

/* ============================ GLOBAL VARIABLES ============================== */

extern bool AuditModeEnabled; /* Display all issues to screen, even those that would not be useful in a CTF */

/* ============================ PROTOTYPES ============================== */

/* ============================ All_RESULTS FUNCTIONS =================== */

/**
 * This function will create and initilize the All_Results struct 
 * This struct contains several linked list for the each issue to be 
 * stored
 */
All_Results *initilize_total_results();

/**
 * This function is used to free up all of the results in memory 
 * called to clean up before termination of the program This method 
 * will dealocate all results in all the linked lists 
 * @param ar This is the All_Results structure
 */
void free_total_results(All_Results *ar);

/**
 * This function will get all issues that match the id for a given category
 * If no issues are found then NULL is returned. 
 * @param head this is the head of the linked list for the current categroy
 * @param v this is the vector to add resutls into, the callee should init the vector
 * @param id this is the issue ID that we're looking for
 * @param linked_list_len the length of the linked list to search through
 * @return true if any issues were found, otherwise false
 */
bool get_all_issues_with_id(Result *head, vec_void_t *v, unsigned long id, int linked_list_len);

/* ============================ RESULT FUNCTIONS ======================== */

/**
 * Wrapper function to add an issue
 * @param severity This is either HIGH, MEDIUM, LOW, INFO
 * @param location This is the location of the issue 
 * @param ar This is the structure containing all of the issues
 * @param name This is the name of the issue
 * @param other This is any additional information to report, can be NULL 
 */
void add_issue(int severity, int mode, char *location, All_Results *ar, char *name, char *other);

/* ============================ PRINT FUNCTIONS ======================== */

/**
 * Prints headings with a banner and color
 * @param s the string to print to the screen
 */
void print_heading(char *s);

/**
 * If the headings section is only going to be one line in length 
 * then we can print it in a nicer format compared to print heading
 * @param s the string to print
 */
void print_heading_oneliner(char *s);