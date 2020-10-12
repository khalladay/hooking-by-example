/*	Hooking-By-RVA

	This program shows how to install a hook in a running process
	that has been built without debug symbols. The hook that
	gets installed is "destructive" in the sense that it doesn't use
	a trampoline, so the original version of the hooked function is
	completely destroyed.

	For this example, we're hooking a member function of an object
	in the target process, and our payload instructions will use
	a private data member of that object, so we have to pay attention
	to what calling convention is being used (to access the "this"
	pointer).
*/

#include "..\hooking_common.h"

#define TARGET_APP_NAME "target-with-functions-from-dll.exe"
#define DLL_NAME "getnum-dll.dll"
#define FUNC2HOOK_NAME "getNum"

const uint8_t hookPayload[] =
{
	0xB8, 0x64, 0x0, 0x0, 0x0, // mov eax, 64h
	0xC3					   // ret
};

//hacky way to get the path to the correct dll for
//whatever the active build config is... saves having to 
//provide the path on the command line, but is otherwise
//not particularly important
void GetPathToDLL(char* outPath, size_t outPathSize)
{
	char relPath[1024];
	char thisAppName[1024];
	GetModuleFileName(NULL, relPath, 1024);
	GetModuleBaseName(GetCurrentProcess(), NULL, thisAppName, 1024);
	char* replaceStart = strstr(relPath, thisAppName);
	const char* dllName = DLL_NAME;
	memcpy(replaceStart, dllName, strlen(dllName));
	memset(replaceStart + strlen(dllName), '\0', &relPath[1024] - (replaceStart + strlen(dllName)));

	_fullpath(outPath, relPath, outPathSize);
}


HMODULE _FindModuleBaseAddress(HANDLE process, const char* targetModule)
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

void* _FindAddressOfRemoteDLLFunction(HANDLE process, const char* dllName, const char* funcName)
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

	HMODULE remoteModuleBase = _FindModuleBaseAddress(process, dllName);

	return (void*)((uint64_t)remoteModuleBase + offsetOfHookFunc);
}


int main(int argc, const char** argv)
{
	bool err;

	//first, find the remote process and the function we want to hook
	DWORD processID = FindPidByName(TARGET_APP_NAME);
	check(processID);

	HANDLE remoteProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	check(remoteProcessHandle);

	char dllPath[1024];
	GetPathToDLL(dllPath, 1024);

	void* func2hook = _FindAddressOfRemoteDLLFunction(remoteProcessHandle, dllPath, FUNC2HOOK_NAME);
	check(func2hook);

	//now write the payload and relay functions into the remote process' address space
	void* payloadAddrInRemoteProcess = AllocPageInTargetProcess(remoteProcessHandle);
	check(payloadAddrInRemoteProcess);
	err = WriteProcessMemory(remoteProcessHandle, payloadAddrInRemoteProcess, hookPayload, sizeof(hookPayload), nullptr);
	check(err);

	void* relayFunc = AllocatePageNearAddressRemote(remoteProcessHandle, func2hook);
	check(relayFunc != nullptr);
	WriteAbsoluteJump64(remoteProcessHandle, relayFunc, payloadAddrInRemoteProcess);

	//finally, write the actual "hook" into the target function.
	WriteRelativeJump(remoteProcessHandle, func2hook, relayFunc);

	return 0;
}