#include "hook-via-dll-injection-payload.h"
#include <stdio.h>
#include <stdint.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

int getNumHookFunc()
{
	return 1;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	return true;
}