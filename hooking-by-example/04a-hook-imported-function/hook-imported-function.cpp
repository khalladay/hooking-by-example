#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h> //for PROCESSENTRY32, needs to be included after windows.h
#include <DbgHelp.h>
#include <Psapi.h> //for EnumProcessModules

#pragma comment (lib, "Dbghelp.lib")

#define checkf(expr, format, ...) if (!(expr))																\
{																											\
    fprintf(stdout, "CHECK FAILED: %s : " format "\n", __func__, ##__VA_ARGS__);	\
	DebugBreak();	\
	exit(-1);		\
}

void printHelp()
{
	printf("DemoHookingApp-DLLInjection-Injection \nUsage: DemoHookingApp-DLLInjection-Injection <process name> <name of dll to hook> <target func name> <path to payload dll> <payload dll func>\n");
}

void* createRemoteThread(DWORD processID, const char* dllPath)
{
	HANDLE handle = OpenProcess(
		PROCESS_QUERY_INFORMATION | //Needed to get a process' token
		PROCESS_CREATE_THREAD |		//for obvious reasons
		PROCESS_VM_OPERATION |		//required to perform operations on address space of process (like WriteProcessMemory)
		PROCESS_VM_WRITE,			//required for WriteProcessMemory
		FALSE,						//don't inherit handle
		processID);

	checkf(handle, "Could not open process with pid %lu", processID);

	//once the process is open, we need to write the name of our dll to that process' memory
	size_t dllPathLen = strlen(dllPath);
	void* dllPathRemote = VirtualAllocEx(
		handle,
		NULL, //let the system decide where to allocate the memory
		dllPathLen,
		MEM_COMMIT, //actually commit the virtual memory
		PAGE_READWRITE); //mem access for committed page

	checkf(dllPathRemote, "Could not allocate % zd bytes in process with pid : % lu", dllPathLen, processID);

	BOOL writeSucceeded = WriteProcessMemory(
		handle,
		dllPathRemote,
		dllPath,
		dllPathLen,
		NULL);

	checkf(writeSucceeded, "Could not write %zd bytes to process with pid %lu", dllPathLen, processID);

	//now get address of LoadLibraryW function inside Kernel32.dll
	//TEXT macro "Identifies a string as Unicode when UNICODE is defined by a preprocessor directive during compilation. Otherwise, ANSI string"
	PTHREAD_START_ROUTINE loadLibraryFunc = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");

	checkf(loadLibraryFunc, "Could not find LoadLibraryA function inside kernel32.dll");

	//now create a thread in remote process that loads our target dll using LoadLibraryA
	HANDLE remoteThread = CreateRemoteThread(
		handle,
		NULL, //default thread security
		0, //stack size for thread
		loadLibraryFunc, //pointer to start of thread function (for us, LoadLibraryA)
		dllPathRemote, //pointer to variable being passed to thread function
		0, //0 means the thread runs immediately after creation
		NULL); //we don't care about getting back the thread identifier

	checkf(remoteThread, "Could not create remote thread.");

	fprintf(stdout, "Success! remote thread started in process %d\n", processID);

	// Wait for the remote thread to terminate
	WaitForSingleObject(remoteThread, INFINITE);

	//once we're done, free the memory we allocated in the remote process for the dllPathname, and shut down
	VirtualFreeEx(handle, dllPathRemote, 0, MEM_RELEASE);
	CloseHandle(remoteThread);
	CloseHandle(handle);

	return dllPathRemote;
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

DWORD findPidByName(const char* name)
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
			printf("PID Found: %lu\n", pid);
			CloseHandle(h);
			return pid;
		}

	} while (Process32Next(h, &singleProcess));

	CloseHandle(h);

	return 0;
}

HMODULE FindModuleBaseAddress(HANDLE process, const char* targetModule)
{
	HMODULE hMods[1024];
	DWORD cbNeeded;

	if (EnumProcessModules(process, hMods, sizeof(hMods), &cbNeeded))
	{
		for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR moduleName[MAX_PATH];

			// Get the full path to the module's file.

			if (GetModuleFileNameEx(process, hMods[i], moduleName,
				sizeof(moduleName) / sizeof(TCHAR)))
			{
				// Print the module name and handle value.
				if (strstr(moduleName, targetModule) != nullptr)
				{
					return hMods[i];
				}
			}
		}
	}

	return 0;
}

void* FindAddressOfRemoteDLLFunction(HANDLE process, const char* dllName, const char* funcName)
{
	//first, load the dll into this process so we can use GetProcAddress to determine the offset
	//of the target function from the DLL base address
	HMODULE localDLL = LoadLibraryEx(dllName, NULL, 0);
	checkf(localDLL, "Could not load dll %s", dllName);
	void* localHookFunc = GetProcAddress(localDLL, funcName);
	checkf(localHookFunc, "Could not find function %s in %s\n", funcName, dllName);

	uint64_t offsetOfHookFunc = (uint64_t)localHookFunc - (uint64_t)localDLL;
	FreeLibrary(localDLL); //free the library, we don't need it anymore.

	//Technically, we could just use the result of GetProcAddress, since in 99% of cases, the base address of the dll
	//in the two processes will be shared thanks to ASLR, but just in case the remote process has relocated the dll, 
	//I'm getting it here separately.

	HMODULE remoteModuleBase = FindModuleBaseAddress(process, dllName);

	return (void*)((uint64_t)remoteModuleBase + offsetOfHookFunc);
}

void* FindAddressOfRemoteFunction(HANDLE process, const char* funcName)
{
	bool err = SymInitialize(process, NULL, true);
	checkf(err, "Error initializing symbol info");

	SYMBOL_INFO symInfo = { 0 };
	symInfo.SizeOfStruct = sizeof(symInfo);
	err = SymFromName(process, funcName, &symInfo);
	checkf(err, "Could not find symbol %s\n", funcName);
	return (void*)symInfo.Address;
}

int main(int argc, const char** argv)
{
	if (argc != 5) printHelp();

	const char* targetProcessName = argv[1];
	const char* targetDLLName = argv[2];
	const char* targetFuncName = argv[3];
	const char* payloadDLLPath = argv[4];
	const char* payloadFuncName = argv[5];

	//inject the hook function
	DWORD processID = findPidByName(targetProcessName);
	checkf(processID, "Could not find process %s\n", targetProcessName);
	void* dllPath = createRemoteThread(processID, payloadDLLPath);

	HANDLE handle = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE,
		processID);
	checkf(handle, "Could not open process with pid %i\n", processID);

	void* remoteHookFunc = FindAddressOfRemoteDLLFunction(handle, payloadDLLPath, payloadFuncName);
	checkf(remoteHookFunc, "Could not find address of injected function in %s\n", targetProcessName);

	void* remoteTargetFunc = FindAddressOfRemoteDLLFunction(handle, targetDLLName, targetFuncName);
	checkf(remoteTargetFunc, "Could not find address of target function %s in %s\n", targetFuncName, targetDLLName);

	void* redirectAddr = AllocatePageNearAddressRemote(handle, remoteTargetFunc);
	checkf(redirectAddr, "Could not allocate page in remote process near %s", targetFuncName);

	//write the redirect function 
	uint8_t redirectFunc[] = { 0x50, //push rax
								0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //mov 64 bit value into rax
								0x48, 0x87, 0x04, 0x24, //xchg rax for rsp
								0xC3 }; //ret

	uint64_t hookFuncAddr = (uint64_t)remoteHookFunc;
	memcpy(&redirectFunc[3], &hookFuncAddr, 8);

	DWORD oldProtect;
	BOOL success = VirtualProtectEx(handle, (void*)remoteTargetFunc, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
	DWORD err = GetLastError();

	bool write = WriteProcessMemory(handle, remoteTargetFunc, redirectFunc, sizeof(redirectFunc), NULL);
	err = GetLastError();
	//now write the E9 jump to the redirect func
	//uint8_t jmp_instruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };
//	int32_t relAddrToRedirector = (uint64_t)redirectAddr - ((uint64_t)remoteTargetFunc + 5);

	//memcpy(jmp_instruction + 1, &relAddrToRedirector, 4);
//	WriteProcessMemory(handle, remoteTargetFunc, jmp_instruction, sizeof(jmp_instruction), NULL);

	return 0;
}