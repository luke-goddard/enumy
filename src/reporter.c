
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

int save_as_json(All_Results *ar, Args *args)
{
    cJSON *root, *infos, *info;
    cJSON *result;
    cJSON *locations;
    cJSON *high_results, *medium_results;
    cJSON *low_results, *info_results;
    Result *current_result;

    FILE *fptr;

    char *out;
    char hostname[MAXSIZE];

    Vector v;

    int search_res;
    int v_tot;

    printf("Generating JSON\n");

    root = cJSON_CreateObject();
    infos = cJSON_CreateArray();
    high_results = cJSON_CreateArray();
    medium_results = cJSON_CreateArray();
    low_results = cJSON_CreateArray();
    info_results = cJSON_CreateArray();

    gethostname(hostname, MAXSIZE - 1);

    // Info section
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

    // Results section
    cJSON_AddItemToObject(root, "high_results", high_results);
    cJSON_AddItemToObject(root, "medium_results", medium_results);
    cJSON_AddItemToObject(root, "low_results", low_results);
    cJSON_AddItemToObject(root, "info_results", info_results);

    for (int current_id = 0; current_id < ar->highest_id; current_id++)
    {
        vector_init(&v);
        search_res = get_all_issues_with_id(ar, &v, current_id);
        if (search_res == NOT_FOUND)
        {
            vector_free(&v);
            continue;
        }
        else if (search_res == HIGH)
        {
            cJSON_AddItemToArray(high_results, result = cJSON_CreateObject());
        }
        else if (search_res == MEDIUM)
        {
            cJSON_AddItemToArray(medium_results, result = cJSON_CreateObject());
        }
        else if (search_res == LOW)
        {
            cJSON_AddItemToArray(low_results, result = cJSON_CreateObject());
        }
        else if (search_res == INFO)
        {
            cJSON_AddItemToArray(info_results, result = cJSON_CreateObject());
        }
        else
        {
            DEBUG_PRINT("Programming error while searching for issue with id %i\n", current_id);
            vector_free(&v);
            continue;
        }

        v_tot = vector_total(&v);
        for (int x = 0; x < v_tot; x++)
        {
            current_result = (Result *)vector_get(&v, x);
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

        vector_free(&v);
    }

    out = cJSON_Print(root);
    if (out == NULL)
    {
        DEBUG_PRINT("%s", "cJSON_Print return NULL");
        printf("Failed generating JSON object\n");
        return false;
    }

    fptr = fopen(args->save_location, "w");

    if (fptr == NULL)
    {
        printf("Failed to open %s\n", args->save_location);
        return false;
    }

    fprintf(fptr, "%s", out);

    free(out);
    cJSON_Delete(root);
    fclose(fptr);

    printf("Json saved at location -> %s\n", args->save_location);

    return true;
}