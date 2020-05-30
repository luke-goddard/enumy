/*
    This header file exposes the writing results functionality. 
    At some point enumy will be expected to write many different types of file 
    formats for example, json, html, xml, csv, yaml 

    Currently only JSON is supported
*/

#pragma once

#include "results.h"
#include "main.h"

/* ============================ PROTOTYPES ============================== */

/**
 * This function takes a completed All_Results struct and uses the results 
 * to populate a JSON file with all the information found inside of the struct 
 * @param ar This struct contains all of the issues found on the system by enumy 
 * @param args is a struct that contains the run time options such as the location to 
 *             save files
 */
int save_as_json(All_Results *ar, Args *args);