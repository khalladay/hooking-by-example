//This program shows how to install a (destructive) inline hook
//into a free function in a different process. "Destructive" 
//in this case just means that the hook payload does not contain a trampoline, 
//so after the hook is installed, the original function is no longer callable.

//this example represents the easiest possible case - the target process has debug
//symbols (to look up function addresses by name)

#include <Windows.h>
#include <memoryapi.h>
#include <process.h>
#include <stdint.h>
#include <wow64apiset.h> // for checking is process is 64 bit
#include <TlHelp32.h> //for PROCESSENTRY32, needs to be included after windows.h
#include <DbgHelp.h>
#include <stdio.h>
#include <Psapi.h>
#pragma comment (lib, "Dbghelp.lib")

#define check(expr) if (!(expr)){ printf("Err: %i\n", GetLastError()); DebugBreak(); exit(-1); }

#if _WIN64
typedef uint64_t addr_t;
#else 
typedef uint32_t addr_t;
#endif

bool IsProcess64Bit(HANDLE process)
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

DWORD FindPidByName(const char* name)
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

void* AllocPageInTargetProcess(HANDLE process)
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

	addr_t startAddr = (addr_t)sysInfo.lpMinimumApplicationAddress;
	int PAGE_SIZE = sysInfo.dwPageSize;
	addr_t startPage = (startAddr - (startAddr % PAGE_SIZE));
	addr_t pageIndex = 0;

	while (1)
	{
		addr_t nextAddr = pageIndex++ * PAGE_SIZE;

		if (nextAddr >= (addr_t)sysInfo.lpMaximumApplicationAddress)
		{
			break;
		}

		void* newPage = VirtualAllocEx(process, (void*)nextAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (newPage)
		{
			return newPage;
		}
	}

	return nullptr;
}

void* AllocatePageNearAddressRemote(HANDLE handle, void* targetAddr)
{
	check(IsProcess64Bit(handle));

	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

	uint64_t startAddr = (uint64_t)targetAddr;
	uint64_t minAddr = min(startAddr - 0x7FFFFF00, (uint64_t)sysInfo.lpMinimumApplicationAddress);
	uint64_t maxAddr = max(startAddr + 0x7FFFFF00, (uint64_t)sysInfo.lpMaximumApplicationAddress);

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
			void* outAddr = VirtualAllocEx(handle, (void*)highAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr)
				return outAddr;
		}

		if (lowAddr > minAddr)
		{
			void* outAddr = VirtualAllocEx(handle, (void*)lowAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
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

void LowercaseInPlace(char* str)
{
	for (int i = 0; str[i]; i++)
	{
		str[i] = tolower(str[i]);
	}
}

HMODULE GetBaseModuleForProcess(HANDLE process)
{
	HMODULE remoteProcessModules[1024];
	DWORD numBytesWrittenInModuleArray = 0;
	BOOL success = EnumProcessModules(process, remoteProcessModules, sizeof(HMODULE) * 1024, &numBytesWrittenInModuleArray);

	if (!success)
	{
		fprintf(stderr, "Error enumerating modules on target process. Error Code %lu \n", GetLastError());
		DebugBreak();
	}

	DWORD numRemoteModules = numBytesWrittenInModuleArray / sizeof(HMODULE);
	CHAR remoteProcessName[256];
	GetModuleFileNameEx(process, NULL, remoteProcessName, 256); //a null module handle gets the process name
	LowercaseInPlace(remoteProcessName);

	MODULEINFO remoteProcessModuleInfo;
	HMODULE remoteProcessModule = 0; //An HMODULE is just the DLL's base address 

	for (DWORD i = 0; i < numRemoteModules; ++i)
	{
		CHAR moduleName[256];

		GetModuleFileNameEx(process, remoteProcessModules[i], moduleName, 256);
		LowercaseInPlace(moduleName);

		if (strcmp(remoteProcessName, moduleName) == 0)
		{
			remoteProcessModule = remoteProcessModules[i];

			success = GetModuleInformation(process, remoteProcessModules[i], &remoteProcessModuleInfo, sizeof(MODULEINFO));
			if (!success)
			{
				fprintf(stderr, "Error getting module information for remote process module\n");
				DebugBreak();
			}
			break;
		}
	}

	return remoteProcessModule;
}

void WriteAbsoluteJump(HANDLE process, void* absJumpMemory, void* addrToJumpTo)
{
	check(IsProcess64Bit(process));

	//this writes the absolute jump instructions into the memory allocated near the target
	//the E9 jump installed in the target function (GetNum) will jump to here
	uint8_t absJumpInstructions[] = { 0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //mov 64 bit value into rax
											0xFF, 0xE0 }; //jmp rax

	uint64_t addrToJumpTo64 = (uint64_t)addrToJumpTo;
	memcpy(&absJumpInstructions[2], &addrToJumpTo64, sizeof(addrToJumpTo64));
	DWORD oldProtect = 0;
	bool err = VirtualProtectEx(process, absJumpMemory, 64, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(err);

	WriteProcessMemory(process, absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions), nullptr);
}

void WriteRelativeJump(HANDLE process, void* func2hook, void* jumpTarget)
{
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

	int64_t relativeToJumpTarget64 = (int64_t)jumpTarget - ((int64_t)func2hook + 5);
	check(relativeToJumpTarget64 < INT32_MAX);

	int32_t relativeToJumpTarget = (int32_t)relativeToJumpTarget64;

	memcpy(jmpInstruction + 1, &relativeToJumpTarget, 4);

	DWORD oldProtect;
	bool err = VirtualProtectEx(process, func2hook, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(err);

	err = WriteProcessMemory(process, func2hook, jmpInstruction, sizeof(jmpInstruction), nullptr);
	check(err);
}

//#define DBGHELP_TRANSLATE_TCHAR 1
int main(int argc, const char** argv)
{
	DWORD processID = FindPidByName("target-with-free-functions.exe");
	check(processID);
	HANDLE remoteProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	check(remoteProcessHandle);

	//this process' pointer size needs to math the target process
	check(IsProcess64Bit(remoteProcessHandle) == (sizeof(addr_t) == 8));

	//if the binary we're hooking has debug symbols (target-with-free-functions does)
	//then it's possible to look up the address of a function by symbol name
	bool err = SymInitialize(remoteProcessHandle, NULL, true);
	check(err);
	SYMBOL_INFO symInfo = { 0 };
	symInfo.SizeOfStruct = sizeof(symInfo);
	err = SymFromName(remoteProcessHandle, "getNum",&symInfo);
	check(err);

	void* func2hook = (void*)symInfo.Address;

	//next step is to write the payload function to the
	//target process' memory
	void* payloadAddrInRemoteProcess = AllocPageInTargetProcess(remoteProcessHandle);
	check(payloadAddrInRemoteProcess);

	uint8_t hookPayloadFuncBytes[] =
	{
		0xB8, 0x64, 0x0, 0x0, 0x0, // mov eax, 64h
		0xC3					   // ret
	};

	err = WriteProcessMemory(remoteProcessHandle, payloadAddrInRemoteProcess, hookPayloadFuncBytes, sizeof(hookPayloadFuncBytes), nullptr);
	check(err);

	void* hookJumpTarget = payloadAddrInRemoteProcess;

	if (IsProcess64Bit(remoteProcessHandle))
	{
		void* absoluteJumpMemory = AllocatePageNearAddressRemote(remoteProcessHandle, func2hook);
		check(absoluteJumpMemory != nullptr);
		WriteAbsoluteJump(remoteProcessHandle, absoluteJumpMemory, payloadAddrInRemoteProcess);
		hookJumpTarget = absoluteJumpMemory;
	}

	WriteRelativeJump(remoteProcessHandle, func2hook, hookJumpTarget);
	return 0;
}