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
#include "utils.h"
#include "main.h"
#include "debug.h"
#include "vector.h"

#include <errno.h>

/* ============================ DEFINES ============================== */

#define URL "https://www.exploitwriteup.com/enumy-results/#"

/* ============================ PROTOTYPES ============================== */

All_Results *initilize_total_results();

Result *create_new_issue();
Result *get_result_high(All_Results *ar, int index);
Result *get_result_medium(All_Results *ar, int index);
Result *get_result_low(All_Results *ar, int index);
Result *get_result_info(All_Results *ar, int index);

void add_issue(int severity, int id, char *location, All_Results *ar, Args *cmdline, char *name, char *other);
void set_issue_description(char *issue_description, Result *result_node);
void set_issue_location(char *issue_location, Result *result_nodee);
void set_issue_name(char *issue_name, Result *result_node);
void set_id(int issue_id, Result *result_node);

bool add_new_result_medium(Result *new_result, All_Results *result, Args *cmdline);
bool add_new_result_high(Result *new_result, All_Results *result, Args *cmdline);
bool add_new_result_info(Result *new_result, All_Results *result, Args *cmdline);
bool add_new_result_low(Result *new_result, All_Results *result, Args *cmdline);

int get_all_issues_with_id(All_Results *ar, Vector *v, int id);

static void add_new_issue(Result *new_result, All_Results *all_results, int category);
static void log_issue_to_screen(Result *new_result, char *severity);
static void free_linked_list(Result *head);

static bool search_category_for_all_id(Result *head, Vector *v, int id, int size);
static bool is_complete(Result *new_result);

static int count_linked_list_length(Result *first_result);

/* ============================ ALL_RESULTS FUNCTIONS ============================== */

// Creates the All_Results struct, should only be called once
All_Results *initilize_total_results()
{
    struct All_Results *all_results = (struct All_Results *)malloc(sizeof(struct All_Results));

    all_results->high = (struct Result *)malloc(sizeof(struct Result));
    if (all_results->high == NULL)
        out_of_memory_err();

    all_results->medium = (struct Result *)malloc(sizeof(struct Result));
    if (all_results->medium == NULL)
    {
        free(all_results->high);
        out_of_memory_err();
    }

    all_results->low = (struct Result *)malloc(sizeof(struct Result));
    if (all_results->low == NULL)
    {
        free(all_results->high);
        free(all_results->medium);
        out_of_memory_err();
    }
    all_results->info = (struct Result *)malloc(sizeof(struct Result));
    if (all_results->info == NULL)
    {
        free(all_results->high);
        free(all_results->medium);
        free(all_results->low);
        out_of_memory_err();
    }

    all_results->high_end_node = all_results->high;
    all_results->medium_end_node = all_results->medium;
    all_results->low_end_node = all_results->low;
    all_results->info_end_node = all_results->info;
    all_results->highest_id = 0;

    all_results->high_tot = 0;
    all_results->medium_tot = 0;
    all_results->low_tot = 0;
    all_results->info_tot = 0;

    all_results->gui_requires_refresh = NO_REFRESH;

    all_results->high->issue_id = FIRST_ID;
    all_results->high->next = NULL;
    all_results->high->previous = NULL;

    all_results->medium->issue_id = FIRST_ID;
    all_results->medium->next = NULL;
    all_results->medium->previous = NULL;

    all_results->low->issue_id = FIRST_ID;
    all_results->low->next = NULL;
    all_results->low->previous = NULL;

    all_results->info->issue_id = FIRST_ID;
    all_results->high->next = NULL;
    all_results->high->previous = NULL;

    pthread_mutex_init(&all_results->mutex, NULL);

    return all_results;
}

void free_total_results(All_Results *ar)
{
    if (ar == NULL)
        return;

    if (ar->high != NULL)
        free_linked_list(ar->high);

    if (ar->medium != NULL)
        free_linked_list(ar->medium);

    if (ar->low != NULL)
        free_linked_list(ar->low);

    if (ar->info != NULL)
        free_linked_list(ar->info);

    free(ar);
}

/**
 * Wrapper function to add an issue
 * @param severity This is either HIGH, MEDIUM, LOW, INFO
 * @param location This is the location of the issue 
 * @param ar This is the structure containing all of the issues
 * @param cmdline This is the commandline arguments 
 * @param name This is the name of the issue
 * @param other This is any additional information to report, can be NULL 
 */
void add_issue(int severity, int id, char *location, All_Results *ar, Args *cmdline, char *name, char *other)
{
    Result *new_result = create_new_issue();
    set_id_and_desc(id, new_result);
    set_other_info(other, new_result);
    set_issue_location(location, new_result);
    set_issue_name(name, new_result);

    if (severity == HIGH)
        add_new_result_high(new_result, ar, cmdline);
    if (severity == MEDIUM)
        add_new_result_high(new_result, ar, cmdline);
    if (severity == LOW)
        add_new_result_high(new_result, ar, cmdline);
    if (severity == INFO)
        add_new_result_high(new_result, ar, cmdline);
}

int get_results_total(All_Results *result)
{
    return (
        get_tot_high(result) +
        get_tot_medium(result) +
        get_tot_low(result) +
        get_tot_info(result));
}

int get_tot_high(All_Results *result)
{
    struct Result *head_ptr = result->high;
    return count_linked_list_length(head_ptr);
}

int get_tot_medium(All_Results *result)
{
    struct Result *head_ptr = result->medium;
    return count_linked_list_length(head_ptr);
}

int get_tot_low(All_Results *result)
{
    struct Result *head_ptr = result->low;
    return count_linked_list_length(head_ptr);
}

int get_tot_info(All_Results *result)
{
    struct Result *head_ptr = result->info;
    return count_linked_list_length(head_ptr);
}

/**
 * This function will get all issues that match the id.
 * If no issues are found then NULL is returned. 
 * @param ar this is the structure containing all of the results that enumy has found
 * @param v this is the vector to add resutls into, the callee should init the vector
 * @param id this is the issue ID that we're looking for
 * @return true if any issues were found, otherwise false
 */
int get_all_issues_with_id(All_Results *ar, Vector *v, int id)
{
    if (search_category_for_all_id(ar->high, v, id, ar->high_tot))
        return HIGH;

    if (search_category_for_all_id(ar->medium, v, id, ar->medium_tot))
        return MEDIUM;

    if (search_category_for_all_id(ar->low, v, id, ar->low_tot))
        return LOW;

    if (search_category_for_all_id(ar->info, v, id, ar->info_tot))
        return INFO;

    return NOT_FOUND;
}

/* ============================ RESULT FUNCTIONS ============================== */

// Creates a base issue with default values
Result *create_new_issue()
{
    struct Result *new_result = (struct Result *)malloc(sizeof(struct Result));

    if (new_result == NULL)
        out_of_memory_err();

    /* set the issues to invalid values so we can test if a new issue is commplete */
    new_result->issue_id = INCOMPLETE_ID;
    new_result->issue_name[0] = '\0';
    new_result->description[0] = '\0';
    new_result->location[0] = '\0';
    new_result->next = NULL;
    new_result->previous = NULL;
    new_result->no_ls = NULL;

    return new_result;
}

Result *get_result_high(All_Results *ar, int index)
{
    Result *current = ar->high;
    for (int i = 0; i <= get_tot_high(ar) && i < index; i++)
        current = current->next;

    return current;
}

Result *get_result_medium(All_Results *ar, int index)
{
    Result *current = ar->medium;
    for (int i = 0; i <= get_tot_medium(ar) && i < index; i++)
        current = current->next;

    return current;
}

Result *get_result_low(All_Results *ar, int index)
{
    Result *current = ar->low;
    for (int i = 0; i <= get_tot_low(ar) && i < index; i++)
        current = current->next;

    return current;
}

Result *get_result_info(All_Results *ar, int index)
{
    Result *current = ar->info;
    for (int i = 0; i <= get_tot_info(ar) && i < index; i++)
        current = current->next;

    return current;
}

// Set id for the base issue
void set_id(int issue_id, Result *result_node)
{
    result_node->issue_id = issue_id;
}

// Set id for the base issue and the description as a
// link to the issue writeup on my website with the id being the
// ancore point to the link
void set_id_and_desc(int issue_id, Result *result_node)
{
    int length = snprintf(NULL, 0, "%d", issue_id);
    char *str = malloc(length + 1);
    if (str == NULL)
    {
        out_of_memory_err();
    }
    snprintf(str, length + 1, "%d", issue_id);

    result_node->issue_id = issue_id;
    strcpy(result_node->description, URL);
    strncat(result_node->description, str, MAXSIZE - 1);
    free(str);
}

// Set issue name for the base issue
void set_issue_name(char *issue_name, Result *result_node)
{
    strncpy(result_node->issue_name, issue_name, MAXSIZE - 1);
}

// Set issue description for the base issue
void set_issue_description(char *issue_description, Result *result_node)
{
    strncpy(result_node->description, issue_description, MAXSIZE - 1);
}

// Set issue location for the base issue
void set_issue_location(char *issue_location, Result *result_node)
{
    strncpy(result_node->location, issue_location, MAXSIZE - 1);
}

// Set the optional other info
void set_other_info(char *other_info, Result *result_node)
{
    strncpy(result_node->other_info, other_info, MAXSIZE - 1);
}

/**
 * Disables the result's location from being printed to screen
 * @param result_node the result to chaange 
 */
void set_no_ls(Result *result_node)
{
    result_node->no_ls = true;
}

// Adds a new fully completed issue to the High linked list
bool add_new_result_high(Result *new_result, All_Results *all_results, Args *cmdline)
{
    if (!is_complete(new_result))
        return false;

    pthread_mutex_lock(&all_results->mutex);
    all_results->high_tot++;
    all_results->gui_requires_refresh = HIGH;
    pthread_mutex_unlock(&all_results->mutex);
    add_new_issue(new_result, all_results, HIGH);

    if (cmdline->enabled_ncurses == false)
    {
        pthread_mutex_lock(&all_results->mutex);
        log_issue_to_screen(new_result, "High");
        pthread_mutex_unlock(&all_results->mutex);
    }

    return true;
}

// Adds a new fully completed issue to the Medium linked list
bool add_new_result_medium(Result *new_result, All_Results *all_results, Args *cmdline)
{
    if (!is_complete(new_result))
        return false;

    pthread_mutex_lock(&all_results->mutex);
    all_results->medium_tot++;
    all_results->gui_requires_refresh = MEDIUM;
    pthread_mutex_unlock(&all_results->mutex);
    add_new_issue(new_result, all_results, MEDIUM);

    if (cmdline->enabled_ncurses == false)
    {
        pthread_mutex_lock(&all_results->mutex);
        log_issue_to_screen(new_result, "Medium");
        pthread_mutex_unlock(&all_results->mutex);
    }

    return true;
}

// Adds a new fully completed issue to the Low linked list
bool add_new_result_low(Result *new_result, All_Results *all_results, Args *cmdline)
{
    if (!is_complete(new_result))
        return false;

    pthread_mutex_lock(&all_results->mutex);
    all_results->low_tot++;
    all_results->gui_requires_refresh = LOW;
    pthread_mutex_unlock(&all_results->mutex);

    add_new_issue(new_result, all_results, LOW);

    if (cmdline->enabled_ncurses == false)
    {
        pthread_mutex_lock(&all_results->mutex);
        log_issue_to_screen(new_result, "Low");
        pthread_mutex_unlock(&all_results->mutex);
    }

    return true;
}

// Adds a new fully completed issue to the Info linked list
bool add_new_result_info(Result *new_result, All_Results *all_results, Args *cmdline)
{
    if (!is_complete(new_result))
        return false;

    pthread_mutex_lock(&all_results->mutex);
    all_results->info_tot++;
    all_results->gui_requires_refresh = INFO;
    pthread_mutex_unlock(&all_results->mutex);

    add_new_issue(new_result, all_results, INFO);

    if (cmdline->enabled_ncurses == false)
    {
        pthread_mutex_lock(&all_results->mutex);
        log_issue_to_screen(new_result, "Info");
        pthread_mutex_unlock(&all_results->mutex);
    }

    return true;
}

/** 
 * This function will search through a given linked list for
 * any issues with the id
 * @param head this is the head of the linked list for the category you want to search
 * @param id this is the issue id that we're searching for
 * @param v this is a vector to store the results in 
 * @param size this is the number of nodes in the linked list
 * @return true if anything was found
 */
static bool search_category_for_all_id(Result *head, Vector *v, int id, int size)
{
    Result *current = head;
    bool found = false;

    for (int i = 0; i < size; i++)
    {
        if (current == NULL)
        {
            DEBUG_PRINT("%s", "Somthing has gone wrong with the results linked list, found invalid pointer\n");
            return false;
        }

        if (current->issue_id == id)
        {
            vector_add(v, current);
            found = true;
        }
        current = current->next;
    }
    return found;
}

/* ============================ PRINT FUNCTIONS ============================== */

/**
 * Prints headings with a banner and color
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
 */
void print_heading_oneliner(char *s)
{
    printf("%s%-20s%s ", COLOR_INFO, s, COLOR_RESET);
}

/* ============================ STATIC FUNCTIONS ============================== */

// Tests to make sure that issue stuct is completed
// has side effect of printing incomplete structs
static bool is_complete(Result *new_result)
{
    if (
        (new_result->issue_id != INCOMPLETE_ID) &&
        (new_result->issue_name[0] != '\0') &&
        ((new_result->location[0] != '\0') || new_result->no_ls))
        return true;

    DEBUG_PRINT("%s\n", "New issue failed the complitaion check");
    log_issue_to_screen(new_result, "Failed");
    return false;
}

/* Only called if programmer forgot to set all values 
of the struct before adding to linked list */
static void log_issue_to_screen(Result *new_result, char *category)
{
    char ls_cmd[MAXSIZE * 2];
    char ls_result[MAXSIZE];
    char *color_code;

    if (new_result->no_ls == false)
    {
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
    {
        ls_result[0] = '\0';
    }

    if (strcmp(category, "High") == 0)
        color_code = COLOR_HIGH;

    else if (strcmp(category, "Medium") == 0)
        color_code = COLOR_MEDIUM;

    else if (strcmp(category, "Low") == 0)
        color_code = COLOR_LOW;

    else
        color_code = COLOR_INFO;

    printf("Severity: %s%-7s%s Name: %-80s",
           color_code, category, COLOR_RESET,
           new_result->issue_name);
    printf("%s", ls_result);
}

// Finds the correct linked list, if the first element in the link list is the dummy issue
// then swap it with the new result. Updates the saved end nodes.
static void add_new_issue(Result *new_result, All_Results *all_results, int category)
{
    pthread_mutex_lock(&all_results->mutex);
    struct Result *old_head, *old_ptr;

    if (new_result->issue_id > all_results->highest_id)
        all_results->highest_id = new_result->issue_id;

    switch (category)
    {
    case HIGH:
        old_head = all_results->high_end_node;
        all_results->high_end_node = new_result;
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
        old_head = all_results->medium_end_node;
        all_results->medium_end_node = new_result;

        if (all_results->medium->issue_id == FIRST_ID)
        {
            old_ptr = all_results->medium;
            all_results->medium = new_result;
            all_results->medium_end_node = new_result;
        }
        else
        {
            all_results->medium_end_node->previous = old_head;
            old_head->next = new_result;
        }
        break;

    case LOW:
        old_head = all_results->low_end_node;
        all_results->low_end_node = new_result;

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
        old_head = all_results->info_end_node;
        all_results->info_end_node = new_result;

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

static int count_linked_list_length(Result *first_result)
{
    int tot = 0;
    struct Result *next_item = first_result;

    while (next_item != NULL)
    {
        tot++;
        next_item = next_item->next;
    }
    return tot;
}

static void free_linked_list(Result *head)
{
    struct Result *tmp = head;

    while (head != NULL)
    {
        tmp = head;
        head = head->next;
        free(tmp);
    }
}
