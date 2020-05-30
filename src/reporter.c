
/*
    This file is used to log all of the issues found at the end of the scan
*/

#include "debug.h"
#include "results.h"
#include "main.h"
#include "cJSON.h"
#include "vector.h"

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

/* ============================ PROTOTYPES ============================== */

int save_as_json(All_Results *ar, Args *args);

static void add_cat_issue_to_json(cJSON *cat_type, vec_unsigned_long *ids, Result *head, int linked_list_len);

/* ============================ FUNCTIONS ============================== */

/**
 * This function takes a completed All_Results struct and uses the results 
 * to populate a JSON file with all the information found inside of the struct 
 * @param ar This struct contains all of the issues found on the system by enumy 
 * @param args is a struct that contains the run time options such as the location to 
 *             save files
 */
int save_as_json(All_Results *ar, Args *args)
{
    cJSON *root, *infos, *info;
    cJSON *high_results, *medium_results;
    cJSON *low_results, *info_results;

    FILE *fptr;

    char *out;
    char hostname[MAXSIZE] = {'\0'};

    root = cJSON_CreateObject();
    infos = cJSON_CreateArray();
    high_results = cJSON_CreateArray();
    medium_results = cJSON_CreateArray();
    low_results = cJSON_CreateArray();
    info_results = cJSON_CreateArray();

    puts("Generating JSON");
    gethostname(hostname, MAXSIZE - 1);

    /* Info section */
    cJSON_AddItemToObject(root, "runtime_information", infos);
    cJSON_AddItemToArray(infos, info = cJSON_CreateObject());
    cJSON_AddItemToObject(info, "save_location", cJSON_CreateString(args->save_location));
    cJSON_AddItemToObject(info, "ignore_scan_dir", cJSON_CreateString(args->ignore_scan_dir));
    cJSON_AddItemToObject(info, "walk_dir", cJSON_CreateString(args->walk_dir));
    cJSON_AddItemToObject(info, "threads", cJSON_CreateNumber(args->fs_threads));
    cJSON_AddItemToObject(info, "full_scan_enabled", cJSON_CreateBool(args->enabled_full_scans));
    cJSON_AddItemToObject(info, "ncurses_enabled", cJSON_CreateBool(args->enabled_ncurses));
    cJSON_AddItemToObject(info, "test_missing_so", cJSON_CreateBool(args->enabled_missing_so));
    cJSON_AddItemToObject(info, "uid", cJSON_CreateNumber(getuid()));
    cJSON_AddItemToObject(info, "euid", cJSON_CreateNumber(geteuid()));
    cJSON_AddItemToObject(info, "gid", cJSON_CreateNumber(getgid()));
    cJSON_AddItemToObject(info, "egid", cJSON_CreateNumber(getegid()));
    cJSON_AddItemToObject(info, "hostname", cJSON_CreateString(hostname));
    cJSON_AddItemToObject(info, "version", cJSON_CreateString(VERSION));

    /* Results section */
    cJSON_AddItemToObject(root, "high_results", high_results);
    cJSON_AddItemToObject(root, "medium_results", medium_results);
    cJSON_AddItemToObject(root, "low_results", low_results);
    cJSON_AddItemToObject(root, "info_results", info_results);

    /* Actualy add the issues */
    add_cat_issue_to_json(high_results, ar->high_ids, ar->high, ar->high_tot);
    add_cat_issue_to_json(medium_results, ar->medium_ids, ar->medium, ar->medium_tot);
    add_cat_issue_to_json(low_results, ar->low_ids, ar->low, ar->low_tot);
    add_cat_issue_to_json(info_results, ar->info_ids, ar->info, ar->info_tot);

    /* Convert to json */
    out = cJSON_Print(root);
    if (out == NULL)
    {
        DEBUG_PRINT("%s", "cJSON_Print return NULL");
        printf("Failed generating JSON object\n");
        return false;
    }

    /* ============================ TODO ============================== */
    /* This check should happen at the start of the program             */
    /* ============================ TODO ============================== */

    /* Save to file */
    fptr = fopen(args->save_location, "w");
    if (fptr == NULL)
    {
        printf("Failed to open %s\n", args->save_location);
        return false;
    }
    fprintf(fptr, "%s", out);
    printf("Json saved at location -> %s\n", args->save_location);

    /* Clean up */
    free(out);
    cJSON_Delete(root);
    fclose(fptr);

    return true;
}

/**
 * This function will add all issues in a category to the json output
 * @param cat_type this is the json oject to add the issue too 
 * @param ids this is the vector containing all unique ids' for the current category
 * @param head this is the head of the linked list for the current category
 * @param linked_list_len The length of the categories linked list 
 */
static void add_cat_issue_to_json(cJSON *cat_type, vec_unsigned_long *ids, Result *head, int linked_list_len)
{
    cJSON *result;

    for (int i = 0; i < ids->length; i++)
    {
        unsigned long current_id = ids->data[i];

        vec_void_t res_ptrs;
        vec_init(&res_ptrs);

        cJSON *locations = cJSON_CreateArray();
        get_all_issues_with_id(head, &res_ptrs, current_id, linked_list_len);
        cJSON_AddItemToArray(cat_type, result = cJSON_CreateObject());
        for (int x = 0; x < res_ptrs.length; x++)
        {
            Result *current_result = res_ptrs.data[x];
            if (x == 0)
            {
                locations = cJSON_CreateArray();
                cJSON_AddItemToObject(result, "issue_id", cJSON_CreateNumber(current_result->issue_id));
                cJSON_AddItemToObject(result, "issue_name", cJSON_CreateString(current_result->issue_name));
                cJSON_AddItemToObject(result, "other_info", cJSON_CreateString(current_result->other_info));
                cJSON_AddItemToObject(result, "locations", locations);
            }
            cJSON_AddItemToArray(locations, cJSON_CreateString(current_result->location));
        }
        vec_deinit(&res_ptrs);
    }
}