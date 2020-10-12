#pragma once
#define DllExport   __declspec( dllexport )

extern "C"
{
	DllExport __declspec(noinline) int GetNum();
}
