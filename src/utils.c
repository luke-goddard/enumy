/*
    CHANGE ME 
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

void print_die(char *msg)
{
    do
    {
        fprintf(stderr, "%s", msg);
        abort();
    } while (0);
}

void out_of_memory_err()
{
    print_die("Fatal: Ran out of memmory");
}