/*
    This file should allow scans to record and log errors without 
    flooding the user's screen with lots of redundant informaiton. 
    It's important to log errors to know how accurate the scan 
    results are. 
*/

#include "results.h"
#include "main.h"
#include "vector.h"
#include "debug.h"

#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

/* ============================ DEFINES ============================== */

#define ERROR_MAX_SIZE 5000 /* MAX size of an error message */
#define FATAL_MSG "FATAL"   /* Fatal id */
#define ERROR_MSG "ERROR"   /* Error id */
#define WARN_MSG "WARNING"  /* Warning id */

/* ============================ GLOABAL VARS  ============================== */

extern bool DEBUG;       /* Enables printing errors to stderr */
extern bool DEBUG_EXTRA; /* Enables printing warning to stderr */

/* ============================ PROTOTYPES ============================== */

void log_fatal(char *msg);
void log_fatal_loc(char *msg, char *loc);
void log_fatal_errno(char *msg, int err);
void log_fatal_errno_loc(char *msg, char *loc, int err);

void log_error(All_Results *ar, char *msg);
void log_error_loc(All_Results *ar, char *msg, char *loc);
void log_error_errno(All_Results *ar, char *msg, int err);
void log_error_errno_loc(All_Results *ar, char *msg, char *loc, int err);

void log_warn(All_Results *ar, char *msg);
void log_warn_loc(All_Results *ar, char *msg, char *loc);
void log_warn_errno(All_Results *ar, char *msg, int err);
void log_warn_errno_loc(All_Results *ar, char *msg, char *loc, int err);

void sort_log(vec_str_t *v);
void unqiue_log(vec_str_t *v);

static void log_loc(vec_str_t *v, char *loc, char *msg, char *id);
static void log_errno(vec_str_t *v, int err, char *msg, char *id);
static void log_errno_loc(vec_str_t *v, char *msg, char *loc, int err, char *id);
static void log_wrapper(vec_str_t *v, char *msg);

static int qcomp(const void *p1, const void *p2);

/* ============================ FUNCTIONS ============================== */

/* ============================ FATAL FUNCTIONS ============================== */

/**
 * This function will just print the error, we don't save it because we will
 * be terminating after the message is displayed
 * @param msg This is the message to log
 */
void log_fatal(char *msg)
{
    fprintf(stderr, "FATAL error has occured, prematurley stopping enumy\n");
    fprintf(stderr, "%s\n", msg);
}

/**
 * This function will just print the error, we don't save it because we will
 * be terminating after the message is displayed, it will also print location
 * @param msg This is the message to log
 * @param loc This is the location of the file that caused the error
 */
void log_fatal_loc(char *msg, char *loc)
{
    fprintf(stderr, "FATAL error has occured, prematurley stopping enumy\n");
    fprintf(stderr, "%s -> %s\n", msg, loc);
}

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the fatal error messages with the converted errno
 * @param msg This is the message to log
 * @param err This is the errno 
 */
void log_fatal_errno(char *msg, int err)
{
    fprintf(stderr, "FATAL error has occured, prematurley stopping enumy\n");
    fprintf(stderr, "%s -> %s\n", msg, strerror(err));
}

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the fatal error messages with the converted errno and files location
 * @param msg This is the message to log
 * @param loc This is the location that caused the error
 * @param err This is the errno 
 */
void log_fatal_errno_loc(char *msg, char *loc, int err)
{
    fprintf(stderr, "FATAL error has occured, prematurley stopping enumy\n");
    fprintf(stderr, "%s -> %s, %s\n", msg, loc, strerror(err));
}

/* ============================ ERROR FUNCTIONS ============================== */

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the error messages
 * @param ar This contains enumy's results and the errors
 * @param msg This is the message to log
 */
void log_error(All_Results *ar, char *msg)
{
    DEBUG_PRINT("ERROR -> %s\n", msg);

    pthread_mutex_lock(&ar->mutex);
    log_wrapper(ar->errors, msg);
    pthread_mutex_unlock(&ar->mutex);
}

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the messages with the converted errno
 * @param ar This contains enumy's results and the errors
 * @param msg This is the error message to display
 * @param loc This is the location of the error
 */
void log_error_loc(All_Results *ar, char *msg, char *loc)
{
    pthread_mutex_lock(&ar->mutex);
    log_loc(ar->errors, msg, loc, ERROR_MSG);
    pthread_mutex_unlock(&ar->mutex);
}

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the messages with the converted errno
 * @param ar This contains enumy's results and the errors
 * @param msg This is the message to log
 * @param err This is the errno 
 */
void log_error_errno(All_Results *ar, char *msg, int err)
{
    pthread_mutex_lock(&ar->mutex);
    log_errno(ar->errors, err, msg, ERROR_MSG);
    pthread_mutex_unlock(&ar->mutex);
}

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the error messages with the converted errno and files location
 * @param msg This is the message to log
 * @param loc This is the location that caused the error
 * @param err This is the errno 
 */
void log_error_errno_loc(All_Results *ar, char *msg, char *loc, int err)
{
    pthread_mutex_lock(&ar->mutex);
    log_errno_loc(ar->errors, msg, loc, err, ERROR_MSG);
    pthread_mutex_unlock(&ar->mutex);
}

/* ============================ WARNING FUNCTIONS ============================== */

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the warning messages
 * @param ar This contains enumy's results and the errors
 * @param msg This is the message to log
 */
void log_warn(All_Results *ar, char *msg)
{
    DEBUG_PRINT_EXTRA("WARNING -> %s\n", msg);

    pthread_mutex_lock(&ar->mutex);
    log_wrapper(ar->warnings, msg);
    pthread_mutex_unlock(&ar->mutex);
}

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the warning messages with the files location
 * @param ar This contains enumy's results and the errors
 * @param msg This is the message to log
 * @param loc This is the location of the file that caused the error
 */
void log_warn_loc(All_Results *ar, char *msg, char *loc)
{
    pthread_mutex_lock(&ar->mutex);
    log_loc(ar->warnings, msg, loc, WARN_MSG);
    pthread_mutex_unlock(&ar->mutex);
}

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the warning messages with the converted errno
 * @param ar This contains enumy's results and the errors
 * @param msg This is the message to log
 * @param err This is the errno 
 */
void log_warn_errno(All_Results *ar, char *msg, int err)
{
    pthread_mutex_lock(&ar->mutex);
    log_errno(ar->warnings, err, msg, WARN_MSG);
    pthread_mutex_unlock(&ar->mutex);
}

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the warning error messages with the converted errno and files location
 * @param ar This contains enumy's results and the errors
 * @param msg This is the message to log
 * @param loc This is the location that caused the error
 * @param err This is the errno 
 */
void log_warn_errno_loc(All_Results *ar, char *msg, char *loc, int err)
{
    pthread_mutex_lock(&ar->mutex);
    log_errno_loc(ar->warnings, msg, loc, err, WARN_MSG);
    pthread_mutex_unlock(&ar->mutex);
}

/**
 * This will sort the vector containing strings into alphabetical order 
 * @param v This is the vector containing strings that we want to sort
 */
void sort_log(vec_str_t *v)
{
    vec_sort(v, qcomp);
}

/**
 * This function is used to unique the log, so that we don't have duplicate errors 
 * @param v The vector containing the logs 
 */
void unqiue_log(vec_str_t *v)
{
    char *previous;
    for (int i = 0; i < v->length; i++)
    {
        if (i == 0)
        {
            previous = v->data[0];
            continue;
        }

        if (strcmp(previous, v->data[i]) == 0)
        {
            vec_splice(v, i, 1);
            i--;
        }
        previous = v->data[i];
    }
}

/* ============================ STATIC FUNCTIONS ============================== */

/**
 * Wrapper function to log an issue that just has a location attached to it
 */
static void log_loc(vec_str_t *v, char *msg, char *loc, char *id)
{
    char merge_msg[ERROR_MAX_SIZE] = {'\0'};

    if (DEBUG)
        fprintf(stderr, "[!] - %s%s -> %s: %s%s\n", COLOR_DIM, id, msg, loc, COLOR_RESET);

    strncpy(merge_msg, msg, sizeof(merge_msg) - 1);
    strncat(merge_msg, " -> ", sizeof(merge_msg) - strlen(merge_msg) - 1);
    strncat(merge_msg, loc, sizeof(merge_msg) - strlen(merge_msg) - 1);

    log_wrapper(v, merge_msg);
}

/**
 * Wrapper function to log an issue that just has a errno attached to it
 */
static void log_errno(vec_str_t *v, int err, char *msg, char *id)
{
    char merge_msg[ERROR_MAX_SIZE] = {'\0'};

    if (DEBUG)
        fprintf(stderr, "[!] - %s%s -> %s: %s%s\n", COLOR_DIM, id, msg, strerror(err), COLOR_RESET);

    strncpy(merge_msg, msg, sizeof(merge_msg) - 1);
    strncat(merge_msg, " -> ", sizeof(merge_msg) - strlen(merge_msg) - 1);
    strncat(merge_msg, strerror(err), sizeof(merge_msg) - strlen(merge_msg) - 1);

    log_wrapper(v, merge_msg);
}

/**
 * Wrapper function to log an issue that just has a errno and location attached to it
 */
static void log_errno_loc(vec_str_t *v, char *msg, char *loc, int err, char *id)
{
    char merge_msg[ERROR_MAX_SIZE] = {'\0'};

    if (DEBUG)
        fprintf(stderr, "[!] - %s%s -> %s: %s %s%s\n", COLOR_DIM, id, msg, strerror(err), loc, COLOR_RESET);

    strncpy(merge_msg, msg, sizeof(merge_msg) - 1);
    strncat(merge_msg, " -> ", sizeof(merge_msg) - strlen(merge_msg) - 1);
    strncat(merge_msg, strerror(err), sizeof(merge_msg) - strlen(merge_msg) - 1);
    strncat(merge_msg, " -> ", sizeof(merge_msg) - strlen(merge_msg) - 1);
    strncat(merge_msg, loc, sizeof(merge_msg) - strlen(merge_msg) - 1);

    log_wrapper(v, merge_msg);
}

/**
 * This function creates a copy of the error message on the heap 
 * and add's it to the vector
 * @param v vector to add the message to
 * @param msg the actual message
 */
static void log_wrapper(vec_str_t *v, char *msg)
{
    char *error_msg = strdup(msg);
    vec_push(v, error_msg);
}

/**
 * This is a compare function used for qsort on the error logs 
 */
static int qcomp(const void *p1, const void *p2)
{
    return strcmp(*(char *const *)p1, *(char *const *)p2);
}