#include "..\hooking_common.h"

#define TARGET_PROGRAM_NAME "C - Target With Non-Virtual Member Functions.exe"

uint8_t hookPayloadFuncBytes[] = {
	0x48, 0x8B, 0x01,		// mov rax, [rcx]
	0x48, 0x83, 0xC0, 0x64, // add rax, 64h
	0xC3
};

int main(int argc, const char** argv)
{
	check(argc == 2);
	bool err;

	//the process we're hooking does NOT have debug symbols, so instead of looking
	//up the function we want to hook by symbol name, we need to find the relative
	//virtual address (RVA) of that function in something like x64dbg, and pass it to
	//this program
	uint64_t inputRVA = _strtoui64(argv[1], nullptr, 16);

	DWORD processID = FindPidByName(TARGET_PROGRAM_NAME);
	check(processID);
	HANDLE remoteProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	check(remoteProcessHandle);
	HMODULE base = GetBaseModuleForProcess(remoteProcessHandle);
	check(base);

	void* func2hook = (void*)((addr_t)base + (addr_t)inputRVA);

	//now that we've found the target function, write the relay and payload into the
	//remote process's address space
	void* payloadFunc = AllocPageInTargetProcess(remoteProcessHandle);
	check(payloadFunc);
	err = WriteProcessMemory(remoteProcessHandle, payloadFunc, hookPayloadFuncBytes, sizeof(hookPayloadFuncBytes), nullptr);
	check(err);

	void* relayFunc = AllocatePageNearAddressRemote(remoteProcessHandle, func2hook);
	check(relayFunc != nullptr);
	WriteAbsoluteJump64(remoteProcessHandle, relayFunc, payloadFunc);

	//finally, write the actual hook into the target function
	WriteRelativeJump(remoteProcessHandle, func2hook, relayFunc);
	return 0;
}