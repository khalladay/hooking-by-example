//this DLL has ASLR disabled and a fixed base address of 0x6FFFFFFF0000
//(see linker settings for how this is set up)

//The idea is that when loaded at this address, it will be too far from the 
//getNum() function in the basic-64bit-inline-hook app to be able to be jumped
//to by an E9 jmp instruction

#pragma once
#define DllExport   __declspec( dllexport )

extern "C"
{
	DllExport int getNumHookFunc();
}
