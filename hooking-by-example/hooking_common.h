#pragma once 
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
	int PAGE_SIZE = sysInfo.dwPageSize;

	void* newPage = VirtualAllocEx(process, NULL, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	return newPage;
}


void* AllocPage()
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	int PAGE_SIZE = sysInfo.dwPageSize;

	void* newPage = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	return newPage;
}

void* AllocatePageNearAddressRemote(HANDLE handle, void* targetAddr)
{
	check(IsProcess64Bit(handle));

	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

	uint64_t startAddr = (uint64_t(targetAddr) & ~(PAGE_SIZE - 1)); //round down to nearest page boundary
	uint64_t minAddr = min(startAddr - 0x7FFFFF00, (uint64_t)sysInfo.lpMinimumApplicationAddress);
	uint64_t maxAddr = max(startAddr + 0x7FFFFF00, (uint64_t)sysInfo.lpMaximumApplicationAddress);

	uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));

	uint64_t pageOffset = 1;
	while (1)
	{
		uint64_t byteOffset = pageOffset * PAGE_SIZE;
		uint64_t highAddr = startPage + byteOffset;
		uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

		bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

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
	return AllocatePageNearAddressRemote(GetCurrentProcess(), targetAddr);
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

//returns the first module called "name" -> only searches for dll name, not whole path
//ie: somepath/subdir/mydll.dll can be searched for with "mydll.dll"
HMODULE FindModuleInProcess(HANDLE process, const char* name)
{
	char* lowerCaseName = _strdup(name);
	_strlwr_s(lowerCaseName, strlen(name) + 1);

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
	_strlwr_s(remoteProcessName, 256);

	MODULEINFO remoteProcessModuleInfo;
	HMODULE remoteProcessModule = 0; //An HMODULE is just the DLL's base address 

	for (DWORD i = 0; i < numRemoteModules; ++i)
	{
		CHAR moduleName[256];
		CHAR absoluteModuleName[256];
		CHAR rebasedPath[256] = { 0 };
		GetModuleFileNameEx(process, remoteProcessModules[i], moduleName, 256);
		_strlwr_s(moduleName, 256);
		char* lastSlash = strrchr(moduleName, '\\');
		if (!lastSlash) lastSlash = strrchr(moduleName, '/');

		char* dllName = lastSlash + 1;

		if (strcmp(dllName, lowerCaseName) == 0)
		{
			remoteProcessModule = remoteProcessModules[i];

			success = GetModuleInformation(process, remoteProcessModules[i], &remoteProcessModuleInfo, sizeof(MODULEINFO));
			check(success);
			free(lowerCaseName);
			return remoteProcessModule;
		}
		//the following string operations are to account for cases where GetModuleFileNameEx
		//returns a relative path rather than an absolute one, the path we get to the module
		//is using a virtual drive letter (ie: one created by subst) rather than a real drive
		char* err = _fullpath(absoluteModuleName, moduleName, 256);
		check(err);
	}

	free(lowerCaseName);
	return 0;
		
}

void PrintModulesForProcess(HANDLE process)
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
	HMODULE remoteProcessModule = 0; //An HMODULE is just the DLL's base address 

	for (DWORD i = 0; i < numRemoteModules; ++i)
	{
		CHAR moduleName[256];
		CHAR absoluteModuleName[256];
		GetModuleFileNameEx(process, remoteProcessModules[i], moduleName, 256);

		//the following string operations are to account for cases where GetModuleFileNameEx
		//returns a relative path rather than an absolute one, the path we get to the module
		//is using a virtual drive letter (ie: one created by subst) rather than a real drive
		char* err = _fullpath(absoluteModuleName, moduleName, 256);
		check(err);
		printf("%s\n", absoluteModuleName);
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
	_strlwr_s(remoteProcessName, 256);

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
		_strlwr_s(rebasedPath, 256);

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

uint32_t WriteMovToRCX(uint8_t* dst, uint64_t val)
{
	check(IsProcess64Bit(GetCurrentProcess()));

	uint8_t movAsmBytes[] =
	{
		0x48, 0xB9, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //movabs 64 bit value into rcx
	};
	memcpy(&movAsmBytes[2], &val, sizeof(uint64_t));
	memcpy(dst, &movAsmBytes, sizeof(movAsmBytes));

	return sizeof(movAsmBytes);

}

uint32_t WriteSaveArgumentRegisters(uint8_t* dst)
{
	uint8_t asmBytes[] =
	{
		0x51, //push rcx
		0x52, //push rdx
		0x41, 0x50, //push r8
		0x41, 0x51, //push r9
		0x48, 0x83, 0xEC, 0x40, //sub rsp, 64 -> space for xmm registers
		0x0F, 0x11, 0x04, 0x24, // movups xmmword ptr [rsp],xmm0
		0x0F, 0x11, 0x4C, 0x24, 0x10, //movups xmmword ptr [rsp+10h],xmm1
		0x0F, 0x11, 0x54, 0x24, 0x20, //movups xmmword ptr [rsp+20h],xmm2
		0x0F, 0x11, 0x5C, 0x24, 0x30 //movups  xmmword ptr [rsp+30h],xmm3
	};
	
	memcpy(dst, &asmBytes, sizeof(asmBytes));
	return sizeof(asmBytes);
}

uint32_t WriteRestoreArgumentRegisters(uint8_t* dst)
{

	uint8_t asmBytes[] =
	{
		0x0F, 0x10, 0x04, 0x24, //movups xmm0,xmmword ptr[rsp]
		0x0F, 0x10, 0x4C, 0x24, 0x10,//movups xmm1,xmmword ptr[rsp + 10h]
		0x0F, 0x10, 0x54, 0x24, 0x20,//movups xmm2,xmmword ptr[rsp + 20h]
		0x0F, 0x10, 0x5C, 0x24, 0x30,//movups xmm3,xmmword ptr[rsp + 30h]
		0x48, 0x83, 0xC4, 0x40,//add rsp,40h
		0x41, 0x59,//pop r9
		0x41, 0x58,//pop r8
		0x5A,//pop rdx
		0x59 //pop rcx
	};

	memcpy(dst, &asmBytes, sizeof(asmBytes));
	return sizeof(asmBytes);
}

uint32_t WriteAddRSP32(uint8_t* dst)
{
	uint8_t addAsmBytes[] =
	{
		0x48, 0x83, 0xC4, 0x20
	};
	memcpy(dst, &addAsmBytes, sizeof(addAsmBytes));
	return sizeof(addAsmBytes);
}

uint32_t WriteSubRSP32(uint8_t* dst)
{
	uint8_t subAsmBytes[] =
	{
		0x48, 0x83, 0xEC, 0x20
	};
	memcpy(dst, &subAsmBytes, sizeof(subAsmBytes));
	return sizeof(subAsmBytes);
}

uint32_t WriteAbsoluteCall64(uint8_t* dst, void* funcToCall)
{
	check(IsProcess64Bit(GetCurrentProcess()));

	uint8_t callAsmBytes[] =
	{
		0x49, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //movabs 64 bit value into r10
		0x41, 0xFF, 0xD2, //call r10
	};
	memcpy(&callAsmBytes[2], &funcToCall, sizeof(void*));
	memcpy(dst, &callAsmBytes, sizeof(callAsmBytes));

	return sizeof(callAsmBytes);
}

uint32_t WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo)
{
	check(IsProcess64Bit(GetCurrentProcess()));

	//this writes the absolute jump instructions into the memory allocated near the target
	//the E9 jump installed in the target function (GetNum) will jump to here
	uint8_t absJumpInstructions[] = { 0x49, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //mov 64 bit value into r10
										0x41, 0xFF, 0xE2 }; //jmp r10

	uint64_t addrToJumpTo64 = (uint64_t)addrToJumpTo;
	memcpy(&absJumpInstructions[2], &addrToJumpTo64, sizeof(addrToJumpTo64));
	memcpy(absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions));
	return sizeof(absJumpInstructions);
}

uint32_t WriteAbsoluteJump64(HANDLE process, void* absJumpMemory, void* addrToJumpTo)
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

uint32_t WriteRelativeJump(void* func2hook, void* jumpTarget)
{
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

	int64_t relativeToJumpTarget64 = (int64_t)jumpTarget - ((int64_t)func2hook + 5);
	check(relativeToJumpTarget64 < INT32_MAX);

	int32_t relativeToJumpTarget = (int32_t)relativeToJumpTarget64;

	memcpy(jmpInstruction + 1, &relativeToJumpTarget, 4);

	DWORD oldProtect;
	bool err = VirtualProtect(func2hook, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(err);

	memcpy(func2hook, jmpInstruction, sizeof(jmpInstruction));
	return sizeof(jmpInstruction);

}

uint32_t WriteRelativeJump(void* func2hook, void* jumpTarget, uint8_t numTrailingNOPs)
{
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

	int64_t relativeToJumpTarget64 = (int64_t)jumpTarget - ((int64_t)func2hook + 5);
	check(relativeToJumpTarget64 < INT32_MAX);

	int32_t relativeToJumpTarget = (int32_t)relativeToJumpTarget64;

	memcpy(jmpInstruction + 1, &relativeToJumpTarget, 4);

	DWORD oldProtect;
	bool err = VirtualProtect(func2hook, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(err);

	memcpy(func2hook, jmpInstruction, sizeof(jmpInstruction));

	uint8_t* byteFunc2Hook = (uint8_t*)func2hook;
	for (int i = 0; i < numTrailingNOPs; ++i)
	{
		memset((void*)(byteFunc2Hook + 5 + i), 0x90, 1);
	}

	return sizeof(jmpInstruction) + numTrailingNOPs;
}


uint32_t WriteRelativeJump(HANDLE process, void* func2hook, void* jumpTarget)
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

	return sizeof(jmpInstruction);
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

void SetOtherThreadsSuspended(bool suspend)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(THREADENTRY32);
		if (Thread32First(hSnapshot, &te))
		{
			do
			{
				if (te.dwSize >= (FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD))
					&& te.th32OwnerProcessID == GetCurrentProcessId()
					&& te.th32ThreadID != GetCurrentThreadId())
				{

					HANDLE thread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
					if (thread != NULL)
					{
						if (suspend)
						{
							SuspendThread(thread);
						}
						else
						{
							ResumeThread(thread);
						}
						CloseHandle(thread);
					}
				}
			} while (Thread32Next(hSnapshot, &te));
		}
	}
}
