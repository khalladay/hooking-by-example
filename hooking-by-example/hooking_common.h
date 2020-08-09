#include <Windows.h>
#include <memoryapi.h>
#include <wow64apiset.h> // for checking is process is 64 bit
#include <TlHelp32.h> //for PROCESSENTRY32, needs to be included after windows.h
#include <Psapi.h>
#include <stdint.h>
#include <stdio.h>

#define check(expr) if (!(expr)){PrintErrorMessageToConsole(GetLastError()); DebugBreak(); exit(-1); }

#if _WIN64
typedef uint64_t addr_t;
#else 
typedef uint32_t addr_t;
#endif

void PrintErrorMessageToConsole(DWORD errorCode)
{
	char errorBuf[1024];
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		errorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		errorBuf,
		1024,
		NULL);

	printf("Error: %i : %s\n", errorCode, errorBuf);
}

BOOL GetErrorMessage(DWORD dwErrorCode, LPTSTR pBuffer, DWORD cchBufferLength)
{
	if (cchBufferLength == 0)
	{
		return FALSE;
	}

	DWORD cchMsg = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,  /* (not used with FORMAT_MESSAGE_FROM_SYSTEM) */
		dwErrorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		pBuffer,
		cchBufferLength,
		NULL);
	return (cchMsg > 0);
}

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
			void* outAddr = VirtualAllocEx(handle, (void*)highAddr, (size_t)PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr)
				return outAddr;
		}

		if (lowAddr > minAddr)
		{
			void* outAddr = VirtualAllocEx(handle, (void*)lowAddr, (size_t)PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
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

void* AllocatePageNearAddress(void* targetAddr)
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

	addr_t startAddr = (addr_t)targetAddr;
	addr_t minAddr = min(startAddr - 0x7FFFFF00, (addr_t)sysInfo.lpMinimumApplicationAddress);
	addr_t maxAddr = max(startAddr + 0x7FFFFF00, (addr_t)sysInfo.lpMaximumApplicationAddress);

	const addr_t PAGE_SIZE = sysInfo.dwPageSize;
	addr_t startPage = (startAddr - (startAddr % PAGE_SIZE));

	addr_t pageOffset = 1;
	while (1)
	{
		addr_t byteOffset = pageOffset * PAGE_SIZE;
		addr_t highAddr = startPage + byteOffset;
		addr_t lowAddr = startPage - byteOffset;

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

void LowercaseInPlace(char* str)
{
	for (int i = 0; str[i]; i++)
	{
		str[i] = tolower(str[i]);
	}
}

//I use subst to alias my development folder to W: 
//this will rebase any virtual drives made by subst to
//their actual drive equivalent, to prevent conflicts. Likely
//not important for most people and can be ignored
void RebaseVirtualDrivePath(const char* path, char* outBuff, size_t outBuffSize)
{
	memset(outBuff, 0, outBuffSize);

	char driveLetter[3] = { 0 };
	memcpy(driveLetter, path, 2);

	char deviceDrive[512];
	QueryDosDevice(driveLetter, deviceDrive, 512);

	const char* virtualDrivePrefix = "\\??\\"; 
	char* prefix = strstr(deviceDrive, virtualDrivePrefix);
	if (prefix)
	{
		size_t replacementLen = strlen(deviceDrive) - strlen(virtualDrivePrefix);
		size_t rebasedPathLen = replacementLen + strlen(path) - 2;
		check(rebasedPathLen < outBuffSize);
		memcpy(outBuff, deviceDrive + strlen(virtualDrivePrefix), replacementLen);
		memcpy(outBuff + replacementLen, &path[2], strlen(path) - 2);
	}
	else
	{
		check(strlen(path) < outBuffSize);
		memcpy(outBuff, path, strlen(path));
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
		CHAR absoluteModuleName[256];
		CHAR rebasedPath[256] = { 0 };
		GetModuleFileNameEx(process, remoteProcessModules[i], moduleName, 256);

		//the following string operations are to account for cases where GetModuleFileNameEx
		//returns a relative path rather than an absolute one, the path we get to the module
		//is using a virtual drive letter (ie: one created by subst) rather than a real drive
		char* err = _fullpath(absoluteModuleName, moduleName, 256);
		check(err);

		RebaseVirtualDrivePath(absoluteModuleName, rebasedPath, 256);
		LowercaseInPlace(rebasedPath);

		if (strcmp(remoteProcessName, rebasedPath) == 0)
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

void WriteAbsoluteJump64(HANDLE process, void* absJumpMemory, void* addrToJumpTo)
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

HMODULE FindModuleBaseAddress(HANDLE process, const char* targetModule)
{
	HMODULE hMods[1024];
	DWORD cbNeeded;

	if (EnumProcessModules(process, hMods, sizeof(hMods), &cbNeeded))
	{
		for (uint32_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
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

	return NULL;
}

void* FindAddressOfRemoteDLLFunction(HANDLE process, const char* dllName, const char* funcName)
{
	//first, load the dll into this process so we can use GetProcAddress to determine the offset
	//of the target function from the DLL base address
	HMODULE localDLL = LoadLibraryEx(dllName, NULL, 0);
	check(localDLL);
	void* localHookFunc = GetProcAddress(localDLL, funcName);
	check(localHookFunc);

	uint64_t offsetOfHookFunc = (uint64_t)localHookFunc - (uint64_t)localDLL;
	FreeLibrary(localDLL); //free the library, we don't need it anymore.

	//Technically, we could just use the result of GetProcAddress, since in 99% of cases, the base address of the dll
	//in the two processes will be shared thanks to ASLR, but just in case the remote process has relocated the dll, 
	//I'm getting it here separately.

	HMODULE remoteModuleBase = FindModuleBaseAddress(process, dllName);

	return (void*)((uint64_t)remoteModuleBase + offsetOfHookFunc);
}