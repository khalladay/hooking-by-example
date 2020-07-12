//it's not as easy to hook 64 bit programs, because it's possible that the hook function for an entrypoint
//is located too far away to use the 32 bit relative jump instruction. 

//This program demonstrates this by manually setting the base address of this exe to _______
//and then loading the dll (basic-64bit-hook-dll) at base address ______ (ASLR is disabled on both projects),
//guaranteeing that the hook function that we want to use (located in the dll) is too far away to just relative jump to

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

#pragma optimize("", off)
int GetNum()
{
	return 99;
}
#pragma optimize("", on)

void* AllocatePageNearAddress(void* targetAddr)
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

	uint64_t startAddr = (uint64_t)targetAddr;
	uint64_t minAddr = max(startAddr - 0x7FFFFF00, (uint64_t)sysInfo.lpMinimumApplicationAddress);
	uint64_t maxAddr = min(startAddr + 0x7FFFFF00, (uint64_t)sysInfo.lpMaximumApplicationAddress);

	const uint64_t PAGE_SIZE = sysInfo.dwPageSize;
	uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));

	uint64_t pageOffset = 1;
	while (1)
	{
		uint64_t byteOffset = pageOffset * PAGE_SIZE;
		uint64_t highAddr = startPage + byteOffset;
		uint64_t lowAddr = startPage - byteOffset;

		bool needsExit = highAddr > maxAddr || lowAddr < minAddr;

		if (highAddr < maxAddr)
		{
			void* outAddr = VirtualAlloc((void*)highAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr)
				return outAddr;
		}

		if (lowAddr > minAddr)
		{
			void* outAddr = VirtualAlloc((void*)lowAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr != nullptr)
				return outAddr;
		}

		pageOffset++;

		if (needsExit)
		{
			break;
		}
	}

	return nullptr;
}

int main(int argc, const char** argv)
{
	checkf(argc == 2, "Usage: basic-64bit-hook.exe <path to hook function dll>");

	HMODULE hookFuncLib = LoadLibraryEx(argv[1], NULL, 0);
	checkf(hookFuncLib, "Failed to load Hook Func Lib, Error %i\n", GetLastError());

	typedef int(__cdecl * HookFuncType)();
	HookFuncType hookFunc = (HookFuncType)GetProcAddress(hookFuncLib, "getNumHookFunc");
	checkf(hookFunc, "Failed to find Hook Function. Error %i\n", GetLastError());

	int64_t relAddr = (uint64_t)hookFunc - ((uint64_t)GetNum + 5);
	const int32_t RELATIVE_JUMP_LIMIT = 0x7FFFFF00;
	//make sure our hook and target functions aren't unintentionally close enough for a 32 bit jump
	checkf(relAddr >= RELATIVE_JUMP_LIMIT || relAddr <= -RELATIVE_JUMP_LIMIT, "Functions are closer than expected");

	printf("Target Func at Address: %p\n", GetNum);
	printf("Hook Func Loaded at Address: %p\n", hookFunc);

	void* nearPage = AllocatePageNearAddress(GetNum);
	checkf(nearPage, "Failed to allocate memory near target function");

	//now that we have memory close enough to jump to from the target function, 
	//we need to write some instructions to perform an absolute jump to the hook
	//function in our dll. 
	printf("Before Hook, getNum() returns %i\n", GetNum());

	uint8_t redirectFunc[] = { 0x50, //push rax
								0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //mov 64 bit value into rax
								0x48, 0x87, 0x04, 0x24, //xchg rax for rsp
								0xC3 }; //ret

	uint64_t hookFuncAddr = (uint64_t)hookFunc;
	memcpy(&redirectFunc[3], &hookFunc, 8);
	memcpy(nearPage, redirectFunc, sizeof(redirectFunc));

	//Now we need to make the target func writable and install the e9 hook
	DWORD oldProtect;
	BOOL success = VirtualProtect(GetNum, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	checkf(success, "Failed to change memory protection of getNum()");

	//now install the e9 hook
	uint32_t relAddrToRedirector = (uint64_t)nearPage - ((uint64_t)GetNum + 5);

	uint8_t jmp_instruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };
	memcpy(jmp_instruction + 1, &relAddrToRedirector, 4);
	memcpy(GetNum, jmp_instruction, sizeof(jmp_instruction));

	printf("After Hook, getNum() returns %i\n", GetNum());

	return 0;
}

