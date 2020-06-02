/*
    This file holds all of the functions relating to storing, appending 
    and retriving results found from scans. There are four categories for 
    results high, medium, low, info 

    High    ->  Critical issues that should be exploitable during a CTF
    
    Medium  ->  Issues that could be could be exploitable or require certain 
                conditions to be met to be exploitable 

    Low     ->  Stuff you would report as a finding, but probably is not that 
                useful durning a pentest 

    Info    ->  Stuff that is not an issue but could be useful during a pentest
                for example, current user, groups, running processes etc 
    
    These results are stored in the All_Results struct, this struct contains a 
    pointer to the head of the linked list for each category
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "results.h"
#include "main.h"
#include "debug.h"
#include "vector.h"

#include <errno.h>

/* ============================ DEFINES ============================== */

#define URL "https://www.exploitwriteup.com/enumy-results/#"

/* ============================ PROTOTYPES ============================== */

All_Results *initilize_total_results();

void add_issue(int severity, char *location, All_Results *ar, char *name, char *other);

bool get_all_issues_with_id(Result *head, vec_void_t *v, unsigned long id, int linked_list_len);

static void add_new_issue(Result *new_result, All_Results *all_results, int category);
static void log_issue_to_screen(Result *new_result, int severity);
static void free_linked_list(Result *head);

static unsigned long hash(char *issue_name);
static void add_new_issue_to_id_vec(vec_unsigned_long *v, unsigned long id);

/* ============================ ALL_RESULTS FUNCTIONS ============================== */

/**
 * This function will create and initilize the All_Results struct 
 * This struct contains several linked list for the each issue to be 
 * stored
 */
All_Results *initilize_total_results()
{
    struct All_Results *all_results = (struct All_Results *)malloc(sizeof(struct All_Results));

    /* Create the high issues linked list */
    all_results->high = (struct Result *)malloc(sizeof(struct Result));
    if (all_results->high == NULL)
    {
        DEBUG_PRINT("%s\n", "Failed to create the high issues linked list");
        exit(EXIT_FAILURE);
    }

    /* Create the medium issues linked list */
    all_results->medium = (struct Result *)malloc(sizeof(struct Result));
    if (all_results->medium == NULL)
    {
        DEBUG_PRINT("%s\n", "Failed to create the medium issues linked list");
        free(all_results->high);
        exit(EXIT_FAILURE);
    }

    /* Create the high low linked list */
    all_results->low = (struct Result *)malloc(sizeof(struct Result));
    if (all_results->low == NULL)
    {
        DEBUG_PRINT("%s\n", "Failed to create the low issues linked list");
        free(all_results->high);
        free(all_results->medium);
        exit(EXIT_FAILURE);
    }

    /* Create the info issues linked list */
    all_results->info = (struct Result *)malloc(sizeof(struct Result));
    if (all_results->info == NULL)
    {
        DEBUG_PRINT("%s\n", "Failed to create the info issues linked list");
        free(all_results->high);
        free(all_results->medium);
        free(all_results->low);
        exit(EXIT_FAILURE);
    }

    /* Create the high issues id vector */
    all_results->high_ids = (vec_unsigned_long *)malloc(sizeof(vec_unsigned_long));
    if (all_results->high_ids == NULL)
    {
        DEBUG_PRINT("%s\n", "Failed to allocate the high ids vector");
        free(all_results->high);
        free(all_results->medium);
        free(all_results->low);
        free(all_results->info);
        exit(EXIT_FAILURE);
    }

    /* Create the medium issues id vector */
    all_results->medium_ids = (vec_unsigned_long *)malloc(sizeof(vec_unsigned_long));
    if (all_results->medium_ids == NULL)
    {
        DEBUG_PRINT("%s\n", "Failed to allocate the medium ids vector");
        free(all_results->high);
        free(all_results->medium);
        free(all_results->low);
        free(all_results->info);
        free(all_results->high_ids);
        exit(EXIT_FAILURE);
    }

    /* Create the low issues id vector */
    all_results->low_ids = (vec_unsigned_long *)malloc(sizeof(vec_unsigned_long));
    if (all_results->low_ids == NULL)
    {
        DEBUG_PRINT("%s\n", "Failed to allocate the medium ids vector");
        free(all_results->high);
        free(all_results->medium);
        free(all_results->low);
        free(all_results->info);
        free(all_results->high_ids);
        free(all_results->medium_ids);
        exit(EXIT_FAILURE);
    }

    /* Create the info issues id vector */
    all_results->info_ids = (vec_unsigned_long *)malloc(sizeof(vec_unsigned_long));
    if (all_results->info_ids == NULL)
    {
        DEBUG_PRINT("%s\n", "Failed to allocate the medium ids vector");
        free(all_results->high);
        free(all_results->medium);
        free(all_results->low);
        free(all_results->info);
        free(all_results->high_ids);
        free(all_results->medium_ids);
        free(all_results->low_ids);
        exit(EXIT_FAILURE);
    }

    /* Create the errors vector */
    all_results->errors = (vec_str_t *)malloc(sizeof(vec_str_t));
    if (all_results->info_ids == NULL)
    {
        DEBUG_PRINT("%s\n", "Failed to allocate the errors vector");
        free(all_results->high);
        free(all_results->medium);
        free(all_results->low);
        free(all_results->info);
        free(all_results->high_ids);
        free(all_results->medium_ids);
        free(all_results->low_ids);
        free(all_results->info_ids);
        exit(EXIT_FAILURE);
    }

    /* Create the errors vector */
    all_results->warnings = (vec_str_t *)malloc(sizeof(vec_str_t));
    if (all_results->info_ids == NULL)
    {
        DEBUG_PRINT("%s\n", "Failed to allocate the errors vector");
        free(all_results->high);
        free(all_results->medium);
        free(all_results->low);
        free(all_results->info);
        free(all_results->high_ids);
        free(all_results->medium_ids);
        free(all_results->low_ids);
        free(all_results->info_ids);
        free(all_results->errors);
        exit(EXIT_FAILURE);
    }

    /* ============================ TODO ============================== */
    /* Linked list should not be initilized with bad values */
    /* ============================ TODO ============================== */

    /* Assigned linked lists tails */
    all_results->high_end_node = all_results->high;
    all_results->medium_end_node = all_results->medium;
    all_results->low_end_node = all_results->low;
    all_results->info_end_node = all_results->info;

    /* Assigned linked lists total values */
    all_results->high_tot = 0;
    all_results->medium_tot = 0;
    all_results->low_tot = 0;
    all_results->info_tot = 0;

    /* Setup high linked list */
    all_results->high->issue_id = FIRST_ID;
    all_results->high->next = NULL;
    all_results->high->previous = NULL;

    /* Setup high linked list */
    all_results->medium->issue_id = FIRST_ID;
    all_results->medium->next = NULL;
    all_results->medium->previous = NULL;

    /* Setup high linked list */
    all_results->low->issue_id = FIRST_ID;
    all_results->low->next = NULL;
    all_results->low->previous = NULL;

    /* Setup high linked list */
    all_results->info->issue_id = FIRST_ID;
    all_results->info->next = NULL;
    all_results->info->previous = NULL;

    /* initilize the vectors */
    vec_init(all_results->high_ids);
    vec_init(all_results->medium_ids);
    vec_init(all_results->low_ids);
    vec_init(all_results->info_ids);
    vec_init(all_results->errors);
    vec_init(all_results->warnings);

    pthread_mutex_init(&all_results->mutex, NULL);

    return all_results;
}

/**
 * This function is used to free up all of the results in memory 
 * called to clean up before termination of the program This method 
 * will dealocate all results in all the linked lists 
 * @param ar This is the All_Results structure
 */
void free_total_results(All_Results *ar)
{
    if (ar == NULL)
        return;

    pthread_mutex_lock(&ar->mutex);

    if (ar->high != NULL)
        free_linked_list(ar->high);

    if (ar->medium != NULL)
        free_linked_list(ar->medium);

    if (ar->low != NULL)
        free_linked_list(ar->low);

    if (ar->info != NULL)
        free_linked_list(ar->info);

    /* Free error/warning vectors */
    for (int i = 0; i < ar->warnings->length; i++)
        free(ar->warnings->data[i]);

    for (int i = 0; i < ar->errors->length; i++)
        free(ar->errors->data[i]);

    /* Destroy the vectors */
    vec_deinit(ar->high_ids);
    vec_deinit(ar->medium_ids);
    vec_deinit(ar->low_ids);
    vec_deinit(ar->info_ids);
    vec_deinit(ar->warnings);
    vec_deinit(ar->errors);

    /* Free the vector pointers */
    free(ar->high_ids);
    free(ar->medium_ids);
    free(ar->low_ids);
    free(ar->info_ids);

    pthread_mutex_unlock(&ar->mutex);
    free(ar);
}

/**
 * Wrapper function to add an issue
 * @param severity This is either HIGH, MEDIUM, LOW, INFO
 * @param location This is the location of the issue 
 * @param ar This is the structure containing all of the issues
 * @param name This is the name of the issue
 * @param other This is any additional information to report, can be NULL 
 */
void add_issue(int severity, char *location, All_Results *ar, char *name, char *other)
{
    struct Result *new_result = (struct Result *)malloc(sizeof(struct Result));

    if (new_result == NULL)
        goto OUT_OF_MEMORY;

    /* ============================ TODO ============================== */
    /* Memset struct                                                    */
    /* ============================ TODO ============================== */

    /* set the issues to invalid values so we can test if a new issue is commplete */
    new_result->issue_id = INCOMPLETE_ID;
    new_result->issue_name[0] = '\0';
    new_result->location[0] = '\0';
    new_result->next = NULL;
    new_result->previous = NULL;
    new_result->no_ls = NULL;

    /* Set ID */
    new_result->issue_id = hash(name);

    /* Set name, loc, other */
    strncpy(new_result->issue_name, name, MAXSIZE - 1);
    strncpy(new_result->location, location, MAXSIZE - 1);
    strncpy(new_result->other_info, other, MAXSIZE - 1);

    /* Insert the issue into the linked list */
    log_issue_to_screen(new_result, severity);
    add_new_issue(new_result, ar, severity);
    return;

OUT_OF_MEMORY:
    printf("Failed to allocate memory when adding a new issue\n");
    exit(EXIT_FAILURE);
}

/**
 * This function will get all issues that match the id.
 * If no issues are found then NULL is returned. 
 * @param head This is the head node of the results that we want to search through
 * @param v this is the vector to add resutls into, the callee should init the vector
 * @param id this is the issue ID that we're looking for
 * @param linked_list_len Length of the linked list to search through
 * @return true if any issues were found, otherwise false
 */
bool get_all_issues_with_id(Result *head, vec_void_t *v, unsigned long id, int linked_list_len)
{
    Result *current = head;
    bool found = false;

    for (int i = 0; i < linked_list_len; i++)
    {
        if (current == NULL)
        {
            DEBUG_PRINT("%s", "Somthing has gone wrong with the results linked list, found invalid pointer\n");
            return false;
        }

        if (current->issue_id == id)
        {
            vec_push(v, (void *)current);
            found = true;
        }
        current = current->next;
    }
    return found;
}

/* ============================ PRINT FUNCTIONS ============================== */

/**
 * Prints headings with a banner and color
 * @param s the string to print to the screen
 */
void print_heading(char *s)
{
    int start = 30;
    int str_len = (int)strlen(s);
    int half_way = start + (str_len / 2);

    bool go_up = true;

    printf("\n%s%s%s\n", COLOR_BOLD, s, COLOR_RESET);
    for (int i = 0; i < str_len; i++)
    {
        if (go_up)
            start++;

        if (!go_up)
            start--;

        if (start == half_way)
            go_up = false;

        printf("\033[38;5;%im-\033[0m", start);
    }
    printf("%s\n", COLOR_RESET);
}

/**
 * If the headings section is only going to be one line in length 
 * then we can print it in a nicer format compared to print heading
 * @param s the string to print
 */
void print_heading_oneliner(char *s)
{
    printf("%s%-20s%s ", COLOR_INFO, s, COLOR_RESET);
}

/* ============================ STATIC FUNCTIONS ============================== */

/**
 * When an issue is added to All_Results through the add_issue function
 * this will log the issue to the screen. The issue has a severity 
 * HIGH, MEDIUM, LOW, INFO. This severity will determine what colour to 
 * print the line as. 
 * 
 * This function also uses ls -ltra --colour=always to print the permissions of 
 * the file. It would be more portable to write are own but there is bigger fish 
 * to fry right now.
 * @param new_result this is the new result that is going to be printed to the screen 
 * @param severity this is the serverity of the issue, HIGH, MEDIUM, LOW, INFO
 */
static void log_issue_to_screen(Result *new_result, int severity)
{
    char ls_result[MAXSIZE];
    char *color_code, *category;

    if ((severity == HIGH) && ShowHigh)
    {
        color_code = COLOR_HIGH;
        category = "HIGH";
    }
    else if ((severity == MEDIUM) && (ShowMed))
    {
        color_code = COLOR_MEDIUM;
        category = "MEDIUM";
    }
    else if ((severity == LOW) && (ShowLow))
    {
        color_code = COLOR_LOW;
        category = "LOW";
    }
    else if ((severity == INFO) && (ShowInfo))
    {
        color_code = COLOR_INFO;
        category = "INFO";
    }
    else
    {
        return;
    }

    if (new_result->no_ls == false)
    {
        char ls_cmd[MAXSIZE * 2];
        snprintf(ls_cmd, MAXSIZE * 2, "ls -ltra \"%s\" --color=always", new_result->location);

        FILE *fp = popen(ls_cmd, "r");
        if (fp == NULL)
        {
            DEBUG_PRINT("Failed to run command -> %s\n", ls_cmd);
            return;
        }
        while (fgets(ls_result, sizeof(ls_result), fp) != NULL)
            ;
        pclose(fp);
    }
    else
        ls_result[0] = '\0';

    printf("Severity: %s%-7s%s Name: %-80s",
           color_code, category, COLOR_RESET,
           new_result->issue_name);
    printf("%s", ls_result);
}

/**
 * This function actually attaches the new issue to the linked list and also increments 
 * the total number of issues found. It should be thread ssage 
 * @param new_result this is the new result to add to the linked list 
 * @param all_results this is the struct containing all of the linked lists 
 * @param category this is the category time for the issue HIGH, MEDIUM, LOW, INFO
 */
static void add_new_issue(Result *new_result, All_Results *all_results, int category)
{
    pthread_mutex_lock(&all_results->mutex);
    struct Result *old_head, *old_ptr;

    switch (category)
    {
    case HIGH:
        all_results->high_tot++;
        old_head = all_results->high_end_node;
        all_results->high_end_node = new_result;
        add_new_issue_to_id_vec(all_results->high_ids, new_result->issue_id);
        if (all_results->high->issue_id == FIRST_ID)
        {
            old_ptr = all_results->high;
            all_results->high = new_result;
            all_results->high_end_node = new_result;
            free(old_ptr);
        }
        else
        {
            all_results->high_end_node->previous = old_head;
            old_head->next = new_result;
        }
        break;

    case MEDIUM:
        all_results->medium_tot++;
        old_head = all_results->medium_end_node;
        all_results->medium_end_node = new_result;
        add_new_issue_to_id_vec(all_results->medium_ids, new_result->issue_id);

        if (all_results->medium->issue_id == FIRST_ID)
        {
            old_ptr = all_results->medium;
            all_results->medium = new_result;
            all_results->medium_end_node = new_result;
            free(old_ptr);
        }
        else
        {
            all_results->medium_end_node->previous = old_head;
            old_head->next = new_result;
        }
        break;

    case LOW:
        all_results->low_tot++;
        old_head = all_results->low_end_node;
        all_results->low_end_node = new_result;
        add_new_issue_to_id_vec(all_results->low_ids, new_result->issue_id);

        if (all_results->low->issue_id == FIRST_ID)
        {
            old_ptr = all_results->low;
            all_results->low = new_result;
            all_results->low_end_node = new_result;
            free(old_ptr);
        }
        else
        {
            all_results->low_end_node->previous = old_head;
            old_head->next = new_result;
        }
        break;

    case INFO:
        all_results->info_tot++;
        old_head = all_results->info_end_node;
        all_results->info_end_node = new_result;
        add_new_issue_to_id_vec(all_results->info_ids, new_result->issue_id);

        if (all_results->info->issue_id == FIRST_ID)
        {
            old_ptr = all_results->info;
            all_results->info = new_result;
            all_results->info_end_node = new_result;
            free(old_ptr);
        }
        else
        {
            all_results->info_end_node->previous = old_head;
            old_head->next = new_result;
        }
        break;

    default:
        DEBUG_PRINT("Programming error, category was not found -> %i\n", category);
    }

    new_result->next = NULL;
    all_results->high_end_node->next = NULL;
    all_results->medium_end_node->next = NULL;
    all_results->low_end_node->next = NULL;
    all_results->info_end_node->next = NULL;
    pthread_mutex_unlock(&all_results->mutex);
}

/**
 * This function is used to clear out a linked list. It works by 
 * 
 * freeing each node in the linked list.
 * @param head this is the first node in the linked list 
 */
static void free_linked_list(Result *head)
{
    while (head != NULL)
    {
        struct Result *tmp = head;
        head = head->next;
        free(tmp);
    }
}

/**
 * Hash function used to convert issue_name to issue_id 
 * @param issue_name name of the issue to get the hash for 
 */
static unsigned long hash(char *issue_name)
{
    unsigned long hash = 5381;
    int c;

    while ((c = *issue_name++))
        hash = ((hash << 5) + hash) + c;

    return hash;
}

/**
 * This function will try and find the issue id inside of the vector
 * if it's not found then we will add it to the vector. We do this to
 * make searching via ID easier when it comes to report the results 
 * @param v This is the vector containg all unique issue id's for the current issue category
 * @param id This is the id to potentially add
 */
static void add_new_issue_to_id_vec(vec_unsigned_long *v, unsigned long id)
{
    for (int i = 0; i < v->length; i++)
    {
        if (v->data[i] == id)
            return;
    }
    vec_push(v, id);
}