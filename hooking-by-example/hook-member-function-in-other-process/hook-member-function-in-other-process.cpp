#include <stdio.h>
#include <Windows.h>
#include <memoryapi.h>
#include <wow64apiset.h> // for checking is process is 64 bit
#include <TlHelp32.h> //for PROCESSENTRY32, needs to be included after windows.h
#include <stdint.h>

#define check(expr) if (!(expr)){ DebugBreak(); exit(-1); }

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


int main(int argc, const char** argv)
{
	DWORD processID = FindPidByName(argv[1]);
	check(processID);

	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	check(handle);

	return 0;
}