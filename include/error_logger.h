#include "results.h"
#include "main.h"

/* ============================ PROTOTYPES FATAL ============================== */

/**
 * This function will just print the error, we don't save it because we will
 * be terminating after the message is displayed
 * @param msg This is the message to log
 */
void log_fatal(char *msg);

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the fatal messages with the files location
 * @param ar This contains enumy's results and the errors
 * @param msg This is the message to log
 * @param loc This is the location of the file that caused the error
 */
void log_fatal_loc(All_Results *ar, char *msg, char *loc);

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the fatal error messages
 * @param msg This is the message to log with the converted errno
 * @param errno This is the errno 
 */
void log_fatal_errno(char *msg, int err);

/* ============================ PROTOTYPES ERROR ============================== */

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the error messages
 * @param ar This contains enumy's results and the errors
 * @param msg This is the message to log
 */
void log_error(All_Results *ar, char *msg);

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the warning messages with the files location
 * @param ar This contains enumy's results and the errors
 * @param msg This is the message to log
 * @param loc This is the location of the file that caused the error
 */
void log_error_loc(All_Results *ar, char *msg, char *loc);

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the error messages with the converted errono
 * @param ar This contains enumy's results and the errors
 * @param msg This is the message to log
 * @param errno This is the errno 
 */
void log_error_errno(All_Results *ar, char *msg, int err);

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the error messages with the converted errno and files location
 * @param msg This is the message to log
 * @param loc This is the location that caused the error
 * @param errno This is the errno 
 */
void log_error_errno_loc(All_Results *ar, char *msg, char *loc, int err);

/* ============================ PROTOTYPES WARN ============================== */

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the warning messages
 * @param ar This contains enumy's results and the errors
 * @param msg This is the message to log
 */
void log_warn(All_Results *ar, char *msg);

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the warning messages with the files location
 * @param ar This contains enumy's results and the errors
 * @param msg This is the message to log
 * @param loc This is the location of the file that caused the error
 */
void log_warn_loc(All_Results *ar, char *msg, char *loc);

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the warning messages with the converted errno
 * @param ar This contains enumy's results and the errors
 * @param msg This is the message to log
 * @param errno This is the errno 
 */
void log_warn_errno(All_Results *ar, char *msg, int err);

/**
 * This function will store an error message msg, on the heap and add it's 
 * pointer to the warning error messages with the converted errno and files location
 * @param msg This is the message to log
 * @param loc This is the location that caused the error
 * @param errno This is the errno 
 */
void log_warn_errno_loc(All_Results *ar, char *msg, char *loc, int err);

/**
 * This will sort the vector containing strings into alphabetical order 
 * @param v This is the vector containing strings that we want to sort
 */
void sort_log(vec_str_t *v);

/**
 * This function is used to unique the log, so that we don't have duplicate errors 
 * @param v The vector containing the logs 
 */
void unqiue_log(vec_str_t *v);