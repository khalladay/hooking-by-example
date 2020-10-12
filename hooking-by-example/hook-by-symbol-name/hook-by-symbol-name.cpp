/*	Hook-By-Symbol-Name
	
	This program shows how to install a hook in a running process
	that has been built with debug symbols enabled. The hook that
	gets installed is "destructive" in the sense that it doesn't use
	a trampoline, so the original version of the hooked function is 
	completely destroyed. 

	In this case, that doesn't matter, because the original function
	just returns a constant (0), and the hook payload that gets installed
	replaces that with a diffferent constant (100). The payload in this 
	example program is so simple that it can almost entirely ignore calling
	conventions, since it doesn't use function args, and only pollutes raxs
*/

#include "..\hooking_common.h"

#include <DbgHelp.h>
#pragma comment (lib, "Dbghelp.lib")

#define TARGET_PROGRAM_NAME "target-with-free-functions.exe"

const uint8_t hookPayload[] =
{
	0xB8, 0x64, 0x0, 0x0, 0x0, // mov eax, 64h
	0xC3					   // ret
};

void* _AllocPageInTargetProcess(HANDLE process)
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	int PAGE_SIZE = sysInfo.dwPageSize;

	void* newPage = VirtualAllocEx(process, NULL, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	return newPage;
}

DWORD _FindPidByName(const char* name)
{
	HANDLE h;
	PROCESSENTRY32 singleProcess;
	h = CreateToolhelp32Snapshot( //takes a snapshot of specified processes
		TH32CS_SNAPPROCESS, //get all processes
		0); //ignored for SNAPPROCESS

	singleProcess.dwSize = sizeof(PROCESSENTRY32);

	do {

		if (strcmp(singleProcess.szExeFile, name) == 0)
		{
			DWORD pid = singleProcess.th32ProcessID;
			CloseHandle(h);
			return pid;
		}

	} while (Process32Next(h, &singleProcess));

	CloseHandle(h);

	return 0;
}

bool _IsProcess64Bit(HANDLE process)
{
	BOOL isWow64 = false;
	IsWow64Process(process, &isWow64);

	if (isWow64)
	{
		//process is 32 bit, running on 64 bit machine
		return false;
	}
	else
	{
		SYSTEM_INFO sysInfo;
		GetSystemInfo(&sysInfo);
		return sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;
	}
}

uint32_t _WriteAbsoluteJump64(HANDLE process, void* absJumpMemory, void* addrToJumpTo)
{
	check(IsProcess64Bit(process));

	//this writes the absolute jump instructions into the memory allocated near the target
	//the E9 jump installed in the target function (GetNum) will jump to here
	uint8_t absJumpInstructions[] = { 0x49, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //mov 64 bit value into r10
											0x41, 0xFF, 0xE2 }; //jmp r10

	uint64_t addrToJumpTo64 = (uint64_t)addrToJumpTo;
	memcpy(&absJumpInstructions[2], &addrToJumpTo64, sizeof(addrToJumpTo64));

	WriteProcessMemory(process, absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions), nullptr);
	return sizeof(absJumpInstructions);
}

int main(int argc, const char** argv)
{
	//first we actually need to find our process
	DWORD processID = _FindPidByName(TARGET_PROGRAM_NAME);
	check(processID);

	HANDLE remoteProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	check(remoteProcessHandle);

	//this process' pointer size needs to match the target process
	check(_IsProcess64Bit(remoteProcessHandle) == _IsProcess64Bit(GetCurrentProcess));

	//the target program that this program hooks has been built with debug 
	//symbols enabled, which means we can get the address of the func to hook
	//by looking up its name in the symbol table
	bool err = SymInitialize(remoteProcessHandle, NULL, true);
	check(err);
	SYMBOL_INFO symInfo = { 0 };
	symInfo.SizeOfStruct = sizeof(symInfo);
	err = SymFromName(remoteProcessHandle, "getNum", &symInfo);
	check(err);

	void* func2hook = (void*)symInfo.Address;

	//next step is to write the payload function to the victim process' memory
	//usually you'd do this will dll injection, but this example just writes out
	//the machine code for the payload function
	void* payloadAddrInRemoteProcess = _AllocPageInTargetProcess(remoteProcessHandle);
	check(payloadAddrInRemoteProcess);
	err = WriteProcessMemory(remoteProcessHandle, payloadAddrInRemoteProcess, hookPayload, sizeof(hookPayload), nullptr);
	check(err);

	//next write the relay function
	void* relayFunc = AllocatePageNearAddressRemote(remoteProcessHandle, func2hook);
	check(relayFunc != nullptr);
	_WriteAbsoluteJump64(remoteProcessHandle, relayFunc, payloadAddrInRemoteProcess);

	//finally, write the actual "hook" into the target function.
	WriteRelativeJump(remoteProcessHandle, func2hook, relayFunc);
	return 0;
}
