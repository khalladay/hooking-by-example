#pragma once

void initializeConsoleFrontend(int windowWidth, int windowHeight, int charsPerLine, int charBufferSize);
void shutdownConsoleFrontend();
void setKeydownFunc(void(*func)(int));

void drawChar(int x, int y, char c);
char getChar(int x, int y);
void clearScreen();
void swapBuffersAndRedraw();
