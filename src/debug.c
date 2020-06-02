#include "debug.h"

#include <stdbool.h>
#include <string.h>

bool ShowHigh = true;
bool ShowMed = true;
bool ShowLow = true;
bool ShowInfo = true;

bool set_disable_print_level(char *s);
bool set_print_lvl_greater_than(char *s);

/**
 * This function parses user input. The string should contain
 * one or more of the following characters h,m,l,i
 * These characters relate to high, medium, low and info
 * @param s The buffer containing user input
 * @return True if the input was not malformed
 */
bool set_disable_print_level(char *s)
{
    int len = strlen(s);
    char current;

    ShowHigh = false;
    ShowMed = false;
    ShowLow = false;
    ShowInfo = false;

    for (int i = 0; i < len; i++)
    {
        current = s[i];
        if (current == 'h' || current == 'H')
        {
            ShowHigh = true;
        }
        else if (current == 'm' || current == 'M')
        {
            ShowMed = true;
        }
        else if (current == 'l' || current == 'L')
        {
            ShowLow = true;
        }
        else if (current == 'i' || current == 'I')
        {
            ShowInfo = true;
        }
        else
        {
            return false;
        }
    }

    return true;
}

/**
 * This function parses user input it should
 * The string should contain one of the following characters h,m,l
 * These characters relate to high, medium, low and info
 * @param s The buffer containing user input
 * @return True if the input was not malformed
 */
bool set_print_lvl_greater_than(char *s)
{

    ShowHigh = false;
    ShowMed = false;
    ShowLow = false;
    ShowInfo = false;

    if (strlen(s) != 0)
    {
        char current = s[0];

        if (current == 'h' || current == 'H')
        {
            ShowHigh = true;
            return true;
        }
        if (current == 'm' || current == 'M')
        {
            ShowHigh = true;
            ShowMed = true;
            return true;
        }
        if (current == 'l' || current == 'L')
        {
            ShowHigh = true;
            ShowMed = true;
            ShowLow = true;
            return true;
        }
        else
        {
            return false;
        }
    }
    return false;
}