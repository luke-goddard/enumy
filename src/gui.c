/*
    This file handles all of the Ncurses GUI functionality
*/

#include "gui.h"
#include "utils.h"
#include "results.h"

#include <locale.h>
#include <stdlib.h>
#include <ncurses.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

#define UPDATE_SECS 1
#define HORIZONTAL_BORDER 61
#define VERTICAL_BORDER 124
#define CORNER_SYMBOL 43

#define HIGH_COLOUR_SCHEME 8
#define MEDIUM_COLOUR_SCHEME 7
#define LOW_COLOUR_SCHEME 6
#define INFO_COLOUR_SCHEME 5

typedef struct Ncurses_Layout Ncurses_Layout;

void update_table(All_Results *all_results, Ncurses_Layout *layout);

void set_category_high(Ncurses_Layout *layout, All_Results *all_results);
void set_category_medium(Ncurses_Layout *layout, All_Results *all_results);
void set_category_low(Ncurses_Layout *layout, All_Results *all_results);
void set_category_info(Ncurses_Layout *layout, All_Results *all_results);

static void setup_colour_scheme(void);
static void setup_logo(WINDOW *logo_window);
static void setup_bars(WINDOW *bars_window);
static void setup_main(WINDOW *main_window);
static void setup_id(WINDOW *id_window);

static void *update_gui(void *update_gui_args);
static void *blink_logo_eyes(void *logo_window);
static Result *get_selected_linked_list(All_Results *all_results, Ncurses_Layout *layout);

typedef struct UpdateGuiArgs
{
    All_Results *all_results;
    Ncurses_Layout *layout;
} UpdateGuiArgs;

/**
 * This function takes a pointer to a struct containing the window layouts 
 * and then initilizes them with the terminals current screen size
 * @param layout a struct containing the different GUI elements 
 * @param all_results a pointer to a struct containing all of the results that enumy finds
 */
void init_ncurses_layout(Ncurses_Layout *layout, All_Results *all_results)
{
    pthread_t logo_eye_blink_thread, update_res_thread;

    UpdateGuiArgs *gui_args_ptr = (UpdateGuiArgs *)malloc(sizeof(UpdateGuiArgs));
    if (gui_args_ptr == NULL)
    {
        out_of_memory_err();
    }
    gui_args_ptr->all_results = all_results;
    gui_args_ptr->layout = layout;

    int logo_height, logo_width, logo_x, logo_y;
    int bars_height, bars_width, bars_x, bars_y;
    int main_height, main_width, main_x, main_y;
    int id_height, id_width, id_x, id_y;

    setlocale(LC_ALL, "");
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    setup_colour_scheme();
    refresh();

    /* logo */
    logo_width = 19;
    logo_height = 7;
    logo_x = 2;
    logo_y = 1;

    /* summary */
    bars_height = 7;
    bars_width = COLS - logo_width - 5;
    bars_x = logo_width + 3;
    bars_y = 1;

    /* main results */
    main_width = COLS - 4;
    main_height = LINES - logo_height - 5;
    main_x = 2;
    main_y = logo_height + 2;

    /* id */
    id_width = COLS - 4;
    id_height = 2;
    id_x = 2;
    id_y = main_y + main_height;

    /* create the windows */
    layout->logo = newwin(logo_height, logo_width, logo_y, logo_x);
    layout->bars = newwin(bars_height, bars_width, bars_y, bars_x);
    layout->main = newwin(main_height, main_width, main_y, main_x);
    layout->id = newwin(id_height, id_width, id_y, id_x);

    layout->cursor_position = 0;
    layout->current_category = HIGH;

    setup_logo(layout->logo);
    setup_bars(layout->bars);
    setup_main(layout->main);
    setup_id(layout->id);

    pthread_create(&update_res_thread, NULL, &update_gui, (void *)gui_args_ptr); // HERE
    pthread_create(&logo_eye_blink_thread, NULL, &blink_logo_eyes, layout->logo);
}

/**
 * This function setups the bar overview GUI element and sets the current 
 * category to high 
 * @param layout this is the ncures layout 
 * @param all_results this is a structure that contains all the results that enumy has found
 */
void set_category_high(Ncurses_Layout *layout, All_Results *all_results)
{
    werase(layout->bars);
    wrefresh(layout->bars);
    wattron(layout->bars, COLOR_PAIR(2));
    wattron(layout->bars, A_BOLD);

    wborder(layout->bars,
            VERTICAL_BORDER, VERTICAL_BORDER,
            HORIZONTAL_BORDER, HORIZONTAL_BORDER,
            CORNER_SYMBOL, CORNER_SYMBOL, CORNER_SYMBOL, CORNER_SYMBOL);

    wattron(layout->bars, COLOR_PAIR(HIGH_COLOUR_SCHEME));
    mvwprintw(layout->bars, 1, 1, " -> High   : ");
    mvwprintw(layout->bars, 2, 1, "    Medium : ");
    mvwprintw(layout->bars, 3, 1, "    Low    : ");
    mvwprintw(layout->bars, 4, 1, "    Info   : ");
    mvwprintw(layout->bars, 5, 1, "    Total  : %i", get_tot_high(all_results));
    wrefresh(layout->bars);
}

/**
 * This function setups the bar overview GUI element and sets the current 
 * category to medium 
 * @param layout this is the ncures layout 
 * @param all_results this is a structure that contains all the results that enumy has found
 */
void set_category_medium(Ncurses_Layout *layout, All_Results *all_results)
{
    werase(layout->bars);
    wrefresh(layout->bars);
    wattron(layout->bars, COLOR_PAIR(2));
    wattron(layout->bars, A_BOLD);

    wborder(layout->bars,
            VERTICAL_BORDER, VERTICAL_BORDER,
            HORIZONTAL_BORDER, HORIZONTAL_BORDER,
            CORNER_SYMBOL, CORNER_SYMBOL, CORNER_SYMBOL, CORNER_SYMBOL);

    wattron(layout->bars, COLOR_PAIR(MEDIUM_COLOUR_SCHEME));
    mvwprintw(layout->bars, 1, 1, "    High   : ");
    mvwprintw(layout->bars, 2, 1, " -> Medium : ");
    mvwprintw(layout->bars, 3, 1, "    Low    : ");
    mvwprintw(layout->bars, 4, 1, "    Info   : ");
    mvwprintw(layout->bars, 5, 1, "    Total  : %i", get_tot_medium(all_results));
    wrefresh(layout->bars);
}

/**
 * This function setups the bar overview GUI element and sets the current 
 * category to low 
 * @param layout this is the ncures layout 
 * @param all_results this is a structure that contains all the results that enumy has found
 */
void set_category_low(Ncurses_Layout *layout, All_Results *all_results)
{
    werase(layout->bars);
    wrefresh(layout->bars);
    wattron(layout->bars, COLOR_PAIR(2));
    wattron(layout->bars, A_BOLD);

    wborder(layout->bars,
            VERTICAL_BORDER, VERTICAL_BORDER,
            HORIZONTAL_BORDER, HORIZONTAL_BORDER,
            CORNER_SYMBOL, CORNER_SYMBOL, CORNER_SYMBOL, CORNER_SYMBOL);

    wattron(layout->bars, COLOR_PAIR(LOW_COLOUR_SCHEME));
    mvwprintw(layout->bars, 1, 1, "    High   : ");
    mvwprintw(layout->bars, 2, 1, "    Medium : ");
    mvwprintw(layout->bars, 3, 1, " -> Low    : ");
    mvwprintw(layout->bars, 4, 1, "    Info   : ");
    mvwprintw(layout->bars, 5, 1, "    Total  : %i", get_tot_low(all_results));
    wrefresh(layout->bars);
}

/**
 * This function setups the bar overview GUI element and sets the current 
 * category to info 
 * @param layout this is the ncures layout 
 * @param all_results this is a structure that contains all the results that enumy has found
 */
void set_category_info(Ncurses_Layout *layout, All_Results *all_results)
{
    werase(layout->bars);
    wrefresh(layout->bars);
    wattron(layout->bars, COLOR_PAIR(2));
    wattron(layout->bars, A_BOLD);

    wborder(layout->bars,
            VERTICAL_BORDER, VERTICAL_BORDER,
            HORIZONTAL_BORDER, HORIZONTAL_BORDER,
            CORNER_SYMBOL, CORNER_SYMBOL, CORNER_SYMBOL, CORNER_SYMBOL);

    wattron(layout->bars, COLOR_PAIR(INFO_COLOUR_SCHEME));
    mvwprintw(layout->bars, 1, 1, "    High   : ");
    mvwprintw(layout->bars, 2, 1, "    Medium : ");
    mvwprintw(layout->bars, 3, 1, "    Low    : ");
    mvwprintw(layout->bars, 4, 1, " -> Info   : ");
    mvwprintw(layout->bars, 5, 1, "    Total  : %i", get_tot_info(all_results));
    wrefresh(layout->bars);
}

/**
 * This function is the entry point for a thread that makes the ascii arts
 * eyes blink 
 * @param logo_window this is the ncurese window for the ascii art
 */
static void *blink_logo_eyes(void *logo_window)
{
    bool eye = TRUE;
    while (1)
    {
        if (eye)
        {
            mvwprintw((WINDOW *)logo_window, 3, 1, "     ███████     ");
            sleep(2);
        }
        else
        {
            mvwprintw((WINDOW *)logo_window, 3, 1, "     █▄███▄█     ");
            sleep(1);
        }
        eye = !eye;
        wrefresh((WINDOW *)logo_window);
    }
    return NULL;
}

/**
 * Setups all the colour schemes for the GUI
 */
static void setup_colour_scheme(void)
{
    start_color();
    init_pair(1, COLOR_BLACK, COLOR_RED);
    init_pair(2, COLOR_YELLOW, COLOR_BLACK);
    init_pair(3, COLOR_WHITE, COLOR_BLACK);
    init_pair(4, COLOR_GREEN, COLOR_BLACK);

    init_pair(HIGH_COLOUR_SCHEME, COLOR_RED, COLOR_BLACK);
    init_pair(MEDIUM_COLOUR_SCHEME, COLOR_YELLOW, COLOR_BLACK);
    init_pair(LOW_COLOUR_SCHEME, COLOR_BLUE, COLOR_BLACK);
    init_pair(INFO_COLOUR_SCHEME, COLOR_GREEN, COLOR_BLACK);
}

/**
 * This function setups up the ascii art for the GUI
 * @param logo_window this is the window containing the ascii 
 */
static void setup_logo(WINDOW *logo_window)
{
    wattron(logo_window, COLOR_PAIR(1));

    wborder(logo_window,
            VERTICAL_BORDER, VERTICAL_BORDER,
            HORIZONTAL_BORDER, HORIZONTAL_BORDER,
            CORNER_SYMBOL, CORNER_SYMBOL, CORNER_SYMBOL, CORNER_SYMBOL);

    mvwprintw(logo_window, 1, 1, " ▄█▀─▄▄▄▄▄▄▄─▀█▄ ");
    mvwprintw(logo_window, 2, 1, " ▀█████████████▀ ");
    mvwprintw(logo_window, 3, 1, "     █▄███▄█     ");
    mvwprintw(logo_window, 4, 1, "      █████      ");
    mvwprintw(logo_window, 5, 1, "      █▀█▀█      ");

    wrefresh(logo_window);
}

/**
 * This function sets up the bar oview and sets the default category to 
 * high 
 * @param bars_window this is the ncursees window
 */
static void setup_bars(WINDOW *bars_window)
{
    werase(bars_window);
    wattron(bars_window, COLOR_PAIR(2));
    wattron(bars_window, A_BOLD);

    wborder(bars_window,
            VERTICAL_BORDER, VERTICAL_BORDER,
            HORIZONTAL_BORDER, HORIZONTAL_BORDER,
            CORNER_SYMBOL, CORNER_SYMBOL, CORNER_SYMBOL, CORNER_SYMBOL);

    wattron(bars_window, COLOR_PAIR(HIGH_COLOUR_SCHEME));
    mvwprintw(bars_window, 1, 1, " -> High   : ");
    mvwprintw(bars_window, 2, 1, "    Medium : ");
    mvwprintw(bars_window, 3, 1, "    Low    : ");
    mvwprintw(bars_window, 4, 1, "    Info   : ");
    wattron(bars_window, COLOR_PAIR(3));
    mvwprintw(bars_window, 5, 1, "    Time   : 0 mins 0 seconds -> Scan Status: Incomplete");
    wrefresh(bars_window);
}

/**
 * This setups the main overview window
 * @param main_window this is a pointer to the ncures main overview window
 */
static void setup_main(WINDOW *main_window)
{
    wattron(main_window, COLOR_PAIR(3));

    wborder(main_window,
            VERTICAL_BORDER, VERTICAL_BORDER,
            HORIZONTAL_BORDER, HORIZONTAL_BORDER,
            CORNER_SYMBOL, CORNER_SYMBOL, CORNER_SYMBOL, CORNER_SYMBOL);

    wrefresh(main_window);
}

/** 
 * This function displays the current users output for 
 * $id 
 * @param id_window this is a pointer to the nucurses id window
 */
static void setup_id(WINDOW *id_window)
{
    char id_summary[1024];
    FILE *fp;
    wattron(id_window, COLOR_PAIR(3));

    fp = popen("id", "r");
    while (fgets(id_summary, sizeof(id_summary), fp) != NULL)
    {
    }

    mvwprintw(id_window, 1, 1, "-> %s <-", id_summary);
    wrefresh(id_window);
    pclose(fp);
}

/**
 * This function is the entry point for a thread 
 * The thread will constantly update the GUI
 * @param gui_args This struct contains the ncures layout and a pointer to the results
 */
static void *update_gui(void *gui_args)
{
    UpdateGuiArgs *args = (UpdateGuiArgs *)gui_args;
    Ncurses_Layout *layout = args->layout;
    All_Results *all_results = args->all_results;
    mvwprintw(layout->main, 1, 1, "    %-10s%-30s%-60s%-60s",
              "ID", "Name", "Description", "Location");

    wrefresh(layout->main);

    while (1)
    {
        // Test if there is new data
        if (all_results->gui_requires_refresh == layout->current_category)
        {
            update_table(all_results, layout);
            all_results->gui_requires_refresh = NO_REFRESH;
        }
        update_table(all_results, layout);
        update_bars(all_results, layout);
        sleep(UPDATE_SECS);
    }
    return NULL;
}

/**
 * This function will update the main overview table
 * @param all_results This is a pointer to all of the results that enumy has found 
 * @param layout This is the ncures layouts 
 */
void update_table(All_Results *all_results, Ncurses_Layout *layout)
{
    int i = 1;
    struct Result *res_ptr = get_selected_linked_list(all_results, layout);

    if (!res_ptr)
    {
        return;
    }

    werase(layout->main);
    wborder(layout->main,
            VERTICAL_BORDER, VERTICAL_BORDER,
            HORIZONTAL_BORDER, HORIZONTAL_BORDER,
            CORNER_SYMBOL, CORNER_SYMBOL, CORNER_SYMBOL, CORNER_SYMBOL);

    mvwprintw(layout->main, 1, 1, "    %-5s%-50s%-80s%-100s",
              "ID", "Name", "Description", "Location");

    wrefresh(layout->main);

    while (res_ptr != NULL)
    {
        i++;
        if (res_ptr->issue_id == FIRST_ID)
        {
            break;
        }
        mvwprintw(layout->main, i, 1, "    %-5i%-50s%-80s%-100s%-10p",
                  res_ptr->issue_id, res_ptr->issue_name,
                  res_ptr->description,
                  res_ptr->location, res_ptr->next);

        wrefresh(layout->main);
        res_ptr = res_ptr->next;
    }
    wrefresh(layout->main);
}

/**
 * This function updates the histogram for the issue count 
 * @param all_results this is issues that enumy has found 
 * @param layout this is the ncureses layout 
 */
void update_bars(All_Results *all_results, Ncurses_Layout *layout)
{
    double high_bar_len, medium_bar_len, low_bar_len, info_bar_len;
    int high_tot, medium_tot, low_tot, info_tot, all_tot;
    double starting_x = 14; // The boiler plate text takes up 13 characters per line
    int x, x_avilable;
    int __attribute__((unused)) y;
    int max = 1;
    char bar = '=';
    double multiplyer;
    char *line_to_print_ptr;

    getmaxyx(layout->bars, y, x);
    if (x < starting_x + 5)
        return; // Terminal too small to display bars

    x_avilable = x - starting_x - 1;

    if ((all_tot = ((high_tot = get_tot_high(all_results)) +
                    (medium_tot = get_tot_medium(all_results)) +
                    (low_tot = get_tot_low(all_results)) +
                    (info_tot = get_tot_info(all_results)))) == 0)
    {
        return;
    }

    // Find percentage for each category and set max to the highest perctage
    if ((high_bar_len = ((double)high_tot / (double)all_tot) * x_avilable) > max)
        max = high_bar_len;

    if ((medium_bar_len = ((double)medium_tot / (double)all_tot) * x_avilable) > max)
        max = medium_bar_len;

    if ((low_bar_len = ((double)low_tot / (double)all_tot) * x_avilable) > max)
        max = low_bar_len;

    if ((info_bar_len = ((double)info_tot / (double)all_tot) * x_avilable) > max)
        max = info_bar_len;

    // Want the biggest bar to take up the whole window, find multipler
    multiplyer = x_avilable / max;
    high_bar_len *= multiplyer;
    medium_bar_len *= multiplyer;
    low_bar_len *= multiplyer;
    info_bar_len *= multiplyer;

    switch (layout->current_category)
    {
    case HIGH:
        set_category_high(layout, all_results);
        break;
    case MEDIUM:
        set_category_medium(layout, all_results);
        break;
    case LOW:
        set_category_low(layout, all_results);
        break;
    case INFO:
        set_category_info(layout, all_results);
        break;
    }

    // print high bar
    line_to_print_ptr = (char *)malloc((int)floor(high_bar_len) + 1);
    if (line_to_print_ptr == NULL)
    {
        out_of_memory_err();
    }
    memset(line_to_print_ptr, bar, (int)floor(high_bar_len));
    line_to_print_ptr[(int)floor(high_bar_len)] = '\0';
    mvwprintw(layout->bars, 1, starting_x, "%s", line_to_print_ptr);
    free(line_to_print_ptr);

    // print medium bar
    line_to_print_ptr = (char *)malloc((int)floor(medium_bar_len) + 1);
    if (line_to_print_ptr == NULL)
    {
        out_of_memory_err();
    }
    memset(line_to_print_ptr, bar, (int)floor(medium_bar_len));
    line_to_print_ptr[(int)floor(medium_bar_len)] = '\0';
    mvwprintw(layout->bars, 2, starting_x, "%s", line_to_print_ptr);
    free(line_to_print_ptr);

    // print low bar
    line_to_print_ptr = (char *)malloc((int)floor(low_bar_len) + 1);
    if (line_to_print_ptr == NULL)
    {
        out_of_memory_err();
    }
    memset(line_to_print_ptr, bar, (int)floor(low_bar_len));
    line_to_print_ptr[(int)floor(low_bar_len)] = '\0';
    mvwprintw(layout->bars, 3, starting_x, "%s", line_to_print_ptr);
    free(line_to_print_ptr);

    // print info bar
    line_to_print_ptr = (char *)malloc((int)floor(info_bar_len) + 1);
    if (line_to_print_ptr == NULL)
    {
        out_of_memory_err();
    }
    memset(line_to_print_ptr, bar, (int)floor(info_bar_len));
    line_to_print_ptr[(int)floor(info_bar_len)] = '\0';
    mvwprintw(layout->bars, 4, starting_x, "%s", line_to_print_ptr);
    free(line_to_print_ptr);

    wattron(layout->bars, COLOR_PAIR(3));
    mvwprintw(layout->bars, 5, 1, "    Total  : %i", all_tot);
    wrefresh(layout->bars);
}

/**
 * This findings the current selected result category (high, low etc) and returns 
 * the pointer to the results for that given category 
 * @param all_results this is a pointer to the results 
 * @param layout this is a pointer to the ncurese layout 
 */
static Result *get_selected_linked_list(All_Results *all_results, Ncurses_Layout *layout)
{
    switch (layout->current_category)
    {
    case HIGH:
        return all_results->high;

    case MEDIUM:
        return all_results->medium;

    case LOW:
        return all_results->low;

    case INFO:
        return all_results->info;

    default:
        return NULL;
    }
}