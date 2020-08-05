//this file demonstrates hooking a function in another process 
//using an injected dll for the payload, rather than writing the payload
//to the target process' address space with WriteProcessBytes
#include "..\hooking_common.h"

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

int main(int argc, const char** argv)
{
	check(argc == 2);

	DWORD processID = FindPidByName("target-with-nonvirtual-member-functions.exe");
	check(processID);

	uint64_t inputRVA = _strtoui64(argv[1], nullptr, 16);
	HANDLE remoteProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	check(remoteProcessHandle);

	HMODULE base = GetBaseModuleForProcess(remoteProcessHandle);
	check(base);
	void* func2hook = (void*)((addr_t)base + (addr_t)inputRVA);


	//	TODO: have the hook payload return the member var with an addition (no rules when you write your own assembly! )

		//next step is to write the payload function to the
		//target process' memory
	void* payloadAddrInRemoteProcess = AllocPageInTargetProcess(remoteProcessHandle);
	check(payloadAddrInRemoteProcess);

	uint8_t hookPayloadFuncBytes[] =
	{
		0xB8, 0x64, 0x0, 0x0, 0x0, // mov eax, 64h
		0xC3					   // ret
	};

	bool err = WriteProcessMemory(remoteProcessHandle, payloadAddrInRemoteProcess, hookPayloadFuncBytes, sizeof(hookPayloadFuncBytes), nullptr);
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