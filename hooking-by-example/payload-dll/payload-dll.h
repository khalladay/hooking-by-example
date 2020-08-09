#pragma once
#define DllExport   __declspec( dllexport )

extern "C"
{
	DllExport int getNum(void* thisPtr);
}
