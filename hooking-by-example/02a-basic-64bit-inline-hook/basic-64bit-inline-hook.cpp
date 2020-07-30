#include <stdio.h>
#include <Windows.h>
#include <memoryapi.h>
#include <stdint.h>
#include <libloaderapi.h>

#define checkf(expr, format, ...) if (!(expr))																\
{																											\
    fprintf(stdout, "CHECK FAILED: %s:%ld:%s " format "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__);	\
	DebugBreak();	\
	exit(-1);		\
}

//has to be unoptimized to prevent MSVC from compiling it down to a constant
#pragma optimize("", off)
int GetNum()
{
	return 99;
}
#pragma optimize("", on)

typedef int(__cdecl* PayloadFuncType)();
PayloadFuncType payloadFunc;

void loadPayloadFunc(const char* dllPath, const char* funcName)
{
	HMODULE hookFuncLib = LoadLibraryEx(dllPath, NULL, 0);
	checkf(hookFuncLib, "Failed to load Hook Func Lib, Error %i\n", GetLastError());

	payloadFunc = (PayloadFuncType)GetProcAddress(hookFuncLib, funcName);
	checkf(payloadFunc, "Failed to find Hook Function. Error %i\n", GetLastError());
}

int main(int argc, const char** argv)
{
	checkf(argc == 2, "Usage: basic-64bit-hook.exe <path to hook function dll>");

	//loading the hook payload from a dll to demonstrate how to hook to
	//a function located too far away for a relative jmp
	loadPayloadFunc(argv[1], "getNumHookFunc");

	//this just verifies that the payload func is in fact, located far enough away for this
	//example to make sense
	{
		int64_t relAddr = (uint64_t)payloadFunc - ((uint64_t)GetNum + 5);
		checkf(relAddr >= 0x7FFFFF00 || relAddr <= -0x7FFFFF00, "Functions are closer than expected");
	}

	printf("Target Func at Address: %p\n", GetNum);
	printf("Payload Func Loaded at Address: %p\n", payloadFunc);

	//now that we have memory close enough to jump to from the target function, 
	//we need to write some instructions to perform an absolute jump to the hook
	//function in our dll. 
	printf("Before Hook, getNum() returns %i\n", GetNum());

	uint8_t jmp_instruction[] = {	0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //mov 64 bit value into rax
									0xFF, 0xE0}; //jmp rax

	DWORD oldProtect;
	BOOL success = VirtualProtect(GetNum, sizeof(jmp_instruction), PAGE_EXECUTE_READWRITE, &oldProtect);
	checkf(success, "Failed to change memory protection of getNum()");

	uint64_t payloadFuncAddr = (uint64_t)payloadFunc;
	memcpy(&jmp_instruction[2], &payloadFuncAddr, sizeof(uint64_t));
	memcpy(GetNum, jmp_instruction, sizeof(jmp_instruction));

	printf("After Hook, getNum() returns %i\n", GetNum());

	return 0;
}

