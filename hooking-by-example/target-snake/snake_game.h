#pragma once

#include <deque>
#include <stdint.h>
#include <mutex>

struct Point
{
	int32_t x;
	int32_t y;
};

enum GameMode
{
	PLAYING,
	GAMEOVER
};

enum KeyInput
{
	NONE,
	KEY_W,
	KEY_A,
	KEY_S,
	KEY_D,
	KEY_SPACE,
	KEY_QUIT
};

class SnakeGame
{
public:
	SnakeGame(int32_t w, int32_t h, int32_t randomSeed);
	~SnakeGame() {};

	void tick();
	void handleInput(char c);

public:
	Point worldSize;
	Point velocity;
	KeyInput pendingInput;
	GameMode currentMode;
	Point targetPos;
	int32_t score;

	std::mutex inputMutex;
	std::deque<Point> snakeSegments;
};
