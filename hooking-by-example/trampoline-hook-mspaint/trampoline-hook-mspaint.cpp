#include "..\hooking_common.h"

#define TARGET_APP_NAME "mspaint.exe"
#define PAYLOAD_DLL_NAME "trampoline-hook-mspaint-payload.dll"
#define PAYLOAD_FUNC_NAME "CreateBrushIndirectPayload"

void InjectPayload(HANDLE process, const char* pathToPayloadDLL)
{
	//write the name of our dll to the target process' memory
	size_t dllPathLen = strlen(pathToPayloadDLL);
	void* dllPathRemote = VirtualAllocEx(
		process,
		NULL, //let the system decide where to allocate the memory
		dllPathLen,
		MEM_COMMIT, //actually commit the virtual memory
		PAGE_READWRITE); //mem access for committed page

	check(dllPathRemote);

	BOOL writeSucceeded = WriteProcessMemory(
		process,
		dllPathRemote,
		pathToPayloadDLL,
		dllPathLen,
		NULL);

	check(writeSucceeded);

	PTHREAD_START_ROUTINE loadLibraryFunc = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32.dll")), "LoadLibraryA");
	check(loadLibraryFunc);

	//create a thread in remote process that loads our target dll using LoadLibraryA
	HANDLE remoteThread = CreateRemoteThread(
		process,
		NULL, //default thread security
		0, //stack size for thread
		loadLibraryFunc, //pointer to start of thread function (for us, LoadLibraryA)
		dllPathRemote, //pointer to variable being passed to thread function
		0, //0 means the thread runs immediately after creation
		NULL); //we don't care about getting back the thread identifier

	check(remoteThread);

	// Wait for the remote thread to terminate
	WaitForSingleObject(remoteThread, INFINITE);

	//once we're done, free the memory we allocated in the remote process for the dllPathname, and shut down
	VirtualFreeEx(process, dllPathRemote, 0, MEM_RELEASE);
	CloseHandle(remoteThread);
}

//hacky way to get the path to the correct payload for
//whatever the active build config is... saves having to 
//provide the path on the command line, but is otherwise
//not particularly important
void GetPathToPayloadDLL(char* outBuff)
{
	char relPath[1024];
	char thisAppName[1024];
	GetModuleFileName(NULL, relPath, 1024);
	GetModuleBaseName(GetCurrentProcess(), NULL, thisAppName, 1024);
	char* replaceStart = strstr(relPath, thisAppName);
	const char* payloadDLLName = PAYLOAD_DLL_NAME;
	memcpy(replaceStart, payloadDLLName, strlen(payloadDLLName));
	memset(replaceStart + strlen(payloadDLLName), '\0', &relPath[1024] - (replaceStart + strlen(payloadDLLName)));

	_fullpath(outBuff, relPath, 1024);
}

int main(int argc, const char** argv)
{
	//5	check(argc == 2);

	DWORD processID = FindPidByName(TARGET_APP_NAME);
	check(processID);

	HANDLE remoteProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	check(remoteProcessHandle);

	char fullPath[1024];
	GetPathToPayloadDLL(fullPath);
	HMODULE mod = FindModuleBaseAddress(remoteProcessHandle, fullPath);

	InjectPayload(remoteProcessHandle, fullPath);

	return 0;
}