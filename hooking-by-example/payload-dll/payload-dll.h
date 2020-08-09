#pragma once
#define DllExport   __declspec( dllexport )

extern "C"
{
	DllExport int __fastcall getNum(void* thisPtr);
}
