#ifndef HYDRA_UI_H
#define HYDRA_UI_H

#include <string>
#include <vector>
#include <curses.h>

/**
 * Console-based UI for Hydra Security Suite using PDCurses
 * Handles windows, colors, menus, and user interaction
 */
class HydraUI {
private:
    WINDOW* mainWin;
    WINDOW* statusWin;
    WINDOW* inputWin;
    int width, height;

    // Color pairs
    const int COLOR_BLACK_GREEN = 1;
    const int COLOR_GREEN_BLACK = 2;
    const int COLOR_WHITE_BLACK = 3;
    const int COLOR_RED_BLACK = 4;
    const int COLOR_YELLOW_BLACK = 5;
    const int COLOR_CYAN_BLACK = 6;

    void initColors() {
        if (has_colors()) {
            start_color();
            init_pair(COLOR_BLACK_GREEN, COLOR_BLACK, COLOR_GREEN);
            init_pair(COLOR_GREEN_BLACK, COLOR_GREEN, COLOR_BLACK);
            init_pair(COLOR_WHITE_BLACK, COLOR_WHITE, COLOR_BLACK);
            init_pair(COLOR_RED_BLACK, COLOR_RED, COLOR_BLACK);
            init_pair(COLOR_YELLOW_BLACK, COLOR_YELLOW, COLOR_BLACK);
            init_pair(COLOR_CYAN_BLACK, COLOR_CYAN, COLOR_BLACK);
        }
    }

public:
    HydraUI() {
        initscr();
        cbreak();
        noecho();
        curs_set(0);
        keypad(stdscr, TRUE);

        getmaxyx(stdscr, height, width);

        // Create windows
        mainWin = newwin(height - 6, width - 4, 2, 2);
        statusWin = newwin(3, width - 4, height - 4, 2);
        inputWin = newwin(1, width - 4, height - 1, 2);

        keypad(mainWin, TRUE);
        keypad(statusWin, TRUE);
        keypad(inputWin, TRUE);

        scrollok(mainWin, TRUE);
        initColors();
        refresh();
    }

    ~HydraUI() {
        endwin();
    }

    void clearMain() {
        werase(mainWin);
        wrefresh(mainWin);
    }

    void drawBorder() {
        erase();

        attron(COLOR_PAIR(COLOR_GREEN_BLACK));
        box(stdscr, 0, 0);

        mvprintw(0, 2, "HYDRA SECURITY SUITE v2.0 [BIOS MODE]");

        mvhline(height - 3, 1, ACS_HLINE, width - 2);
        mvprintw(height - 2, 2, "ARROWS/WASD:Navigate  ENTER:Select  ESC:Back  F10:Exit");

        attroff(COLOR_PAIR(COLOR_GREEN_BLACK));
        refresh();
    }

    void printMain(const string& text, int colorPair = 2) {
        wattrset(mainWin, COLOR_PAIR(colorPair));
        wprintw(mainWin, "%s\n", text.c_str());
        wrefresh(mainWin);
    }

    void printStatus(const string& text, int colorPair = 2) {
        werase(statusWin);
        box(statusWin, 0, 0);
        wattrset(statusWin, COLOR_PAIR(colorPair));
        mvwprintw(statusWin, 1, 2, "%s", text.c_str());
        wrefresh(statusWin);
    }

    string getInput(const string& prompt) {
        echo();
        curs_set(1);

        werase(inputWin);
        wattrset(inputWin, COLOR_PAIR(COLOR_CYAN_BLACK));
        mvwprintw(inputWin, 0, 0, "%s", prompt.c_str());
        wrefresh(inputWin);

        char buffer[256];
        wgetnstr(inputWin, buffer, 255);

        noecho();
        curs_set(0);

        return string(buffer);
    }

    int getChoice(const vector<string>& options, const string& title = "") {
        int selected = 0;
        int key;

        while (true) {
            clearMain();

            if (!title.empty()) {
                wattrset(mainWin, COLOR_PAIR(COLOR_YELLOW_BLACK) | A_BOLD);
                mvwprintw(mainWin, 1, (width - 8 - title.length()) / 2, ">> %s <<", title.c_str());
                wprintw(mainWin, "\n\n");
            }

            for (size_t i = 0; i < options.size(); i++) {
                if (i == selected) {
                    wattrset(mainWin, COLOR_PAIR(COLOR_BLACK_GREEN) | A_BOLD);
                    mvwprintw(mainWin, i + 4, 4, "> %s", options[i].c_str());
                }
                else {
                    wattrset(mainWin, COLOR_PAIR(COLOR_GREEN_BLACK));
                    mvwprintw(mainWin, i + 4, 6, "%s", options[i].c_str());
                }
            }

            wrefresh(mainWin);

            key = wgetch(mainWin);

            switch (key) {
            case KEY_UP:
            case 'w':
            case 'W':
                selected = (selected - 1 + options.size()) % options.size();
                break;
            case KEY_DOWN:
            case 's':
            case 'S':
                selected = (selected + 1) % options.size();
                break;
            case '\r':
            case '\n':
            case KEY_ENTER:
            case ' ':
                return selected;
            case 27:
                return -1;
            case KEY_F(10):
                return -2;
            default:
                break;
            }
        }
    }

    void showMessage(const string& message, int colorPair = 2) {
        printStatus(message, colorPair);
        wgetch(mainWin);
    }

    void showProgress(int current, int total, const string& message = "") {
        werase(statusWin);
        box(statusWin, 0, 0);
        wattrset(statusWin, COLOR_PAIR(COLOR_YELLOW_BLACK));

        if (!message.empty()) {
            mvwprintw(statusWin, 0, 2, "%s", message.c_str());
        }

        float percentage = (float)current / total * 100;
        mvwprintw(statusWin, 1, 2, "Progress: %d/%d (%.1f%%)", current, total, percentage);
        wrefresh(statusWin);
    }

    void drawSplash() {
        clear();
        attron(COLOR_PAIR(COLOR_GREEN_BLACK) | A_BOLD);

        // New logo only (replaces the original)
        string asciiArt[] = {
            "  _    ___     _______  _____            ",
            " | |  | \\ \\   / /  __ \\|  __ \\     /\\    ",
            " | |__| |\\ \\_/ /| |  | | |__) |   /  \\   ",
            " |  __  | \\   / | |  | |  _  /   / /\\ \\  ",
            " | |  | |  | |  | |__| | | \\ \\  / ____ \\ ",
            " |_|  |_|  |_|  |_____/|_|  \\_\\/_/    \\_\\",
            "                                         ",
            "  H Y D R A   S E C U R I T Y           "
        };

        for (int i = 0; i < 8; i++) {
            int x = (width - asciiArt[i].length()) / 2;
            if (x < 0) x = 0;
            mvprintw(5 + i, x, "%s", asciiArt[i].c_str());
        }

        int x = (width - 40) / 2;
        if (x < 0) x = 0;
        mvprintw(height - 8, x, "INITIALIZING SECURITY SUBSYSTEMS...");

        refresh();
        this_thread::sleep_for(chrono::milliseconds(1500));

        attron(COLOR_PAIR(COLOR_GREEN_BLACK));
        mvprintw(height - 4, 10, "[");
        for (int i = 0; i < width - 22; i++) {
            mvprintw(height - 4, 11 + i, "=");
            refresh();
            this_thread::sleep_for(chrono::milliseconds(10));
        }
        mvprintw(height - 4, width - 11, "] 100%%");
        refresh();
        this_thread::sleep_for(chrono::milliseconds(500));

        attroff(COLOR_PAIR(COLOR_GREEN_BLACK));
    }

    void clearScreen() {
        clear();
        refresh();
    }

    WINDOW* getMainWindow() { return mainWin; }
    int getWidth() { return width; }
    int getHeight() { return height; }
};
#endif // HYDRA_UI_H