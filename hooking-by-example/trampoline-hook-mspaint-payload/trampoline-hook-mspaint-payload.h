#pragma once
#define DllExport   __declspec( dllexport )
#include <Windows.h>
#include <wingdi.h>

extern "C"
{
	DllExport HBRUSH CreateBrushIndirectPayload(const LOGBRUSH* brush);
}


