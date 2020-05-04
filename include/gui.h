#pragma once

#include <ncurses.h>

typedef struct Ncurses_Layout
{
    WINDOW *logo; // logo
    WINDOW *bars; // ascii bars
    WINDOW *main; // Main table
    WINDOW *id;   // Displays current UID
    int cursor_position;
    int current_category;
} Ncurses_Layout;

#include "results.h"

void init_ncurses_layout(Ncurses_Layout *layout, All_Results *all_results);
void update_table(All_Results *all_results, Ncurses_Layout *layout);

void set_category_high(Ncurses_Layout *layout, All_Results *all_results);
void set_category_medium(Ncurses_Layout *layout, All_Results *all_results);
void set_category_low(Ncurses_Layout *layout, All_Results *all_results);
void set_category_info(Ncurses_Layout *layout, All_Results *all_results);

void update_bars(All_Results *all_results, Ncurses_Layout *layout);