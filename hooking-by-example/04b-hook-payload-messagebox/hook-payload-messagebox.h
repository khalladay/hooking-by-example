#pragma once
#define DllExport   __declspec( dllexport )

#define WIN32_LEAN_AND_MEAN 
#include <windows.h>
#include <wingdi.h>

extern "C"
{
	DllExport HBRUSH showMessage(const LOGBRUSH* plbrush);
}