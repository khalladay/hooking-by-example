#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h> //for PROCESSENTRY32, needs to be included after windows.h
#include <DbgHelp.h>
#include <stdint.h>

#pragma comment (lib, "Dbghelp.lib")

#define checkf(expr, format, ...) if (!(expr))																\
{																											\
    fprintf(stdout, "CHECK FAILED: %s:%ld:%s " format "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__);	\
	DebugBreak();	\
	exit(-1);		\
}


#pragma optimize("", on)
int getNumHookFunc()
{
	return 1;
}
#pragma optimize("", on)

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


void* AllocatePageNearAddressRemote(HANDLE handle, void* targetAddr)
{
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


//takes the name of the target app as an argument, name of symbol to hook as second arg
//target app must be already running. 
int main(int argc, const char** argv)
{
	DWORD processID = FindPidByName(argv[1]);
	checkf(processID, "Could not find process %s\n", argv[1]);

	HANDLE handle = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE,
		processID);
	checkf(handle, "Could not open process with pid %i\n", processID);

	bool err = SymInitialize(handle, NULL, true);
	checkf(err, "Error initializing symbol info");
	SYMBOL_INFO symInfo = { 0 };
	symInfo.SizeOfStruct = sizeof(symInfo);

	err = SymFromName(handle, argv[2], &symInfo);
	checkf(err, "Could not find symbol %s\n", argv[2]);

	void* redirectAddr = AllocatePageNearAddressRemote(handle, (void*)symInfo.Address);
	uint32_t relAddrToRedirector = (uint64_t)redirectAddr - ((uint64_t)symInfo.Address + 5);

	uint8_t jmp_instruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };
	memcpy(jmp_instruction + 1, &relAddrToRedirector, 4);

	DWORD oldProtect;
	BOOL success = VirtualProtectEx(handle, (void*)symInfo.Address, symInfo.Size, PAGE_EXECUTE_READWRITE, &oldProtect);
	checkf(success, "Failed to change memory protection of getNum()");

	size_t numWritten = 0;

	WriteProcessMemory(handle, (void*)symInfo.Address, jmp_instruction, sizeof(jmp_instruction), &numWritten);
	WriteProcessMemory(handle, redirectAddr, getNumHookFunc, symInfo.Size, &numWritten);
	checkf(err, "Unable to write hook func");

	return 0;
}