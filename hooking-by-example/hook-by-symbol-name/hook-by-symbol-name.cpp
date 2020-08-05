#include "..\hooking_common.h"

#include <DbgHelp.h>
#pragma comment (lib, "Dbghelp.lib")

void WriteAbsoluteJump(HANDLE process, void* absJumpMemory, void* addrToJumpTo);
void WriteRelativeJump(HANDLE process, void* func2hook, void* jumpTarget);

const uint8_t hookPayload[] =
{
	0xB8, 0x64, 0x0, 0x0, 0x0, // mov eax, 64h
	0xC3					   // ret
};

int main(int argc, const char** argv)
{
	bool err; 

	DWORD processID = FindPidByName("target-with-free-functions.exe");
	check(processID);

	HANDLE remoteProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	check(remoteProcessHandle);

	//this process' pointer size needs to match the target process
	check(IsProcess64Bit(remoteProcessHandle) == (sizeof(addr_t) == 8));

	//the target program that this program hooks (target-with-free-functions.exe)
	//has been built with debug symbols enabled, which means we can get the address
	//of the function to hook by looking up it's name in the symbol table
	err = SymInitialize(remoteProcessHandle, NULL, true);
	check(err);
	SYMBOL_INFO symInfo = { 0 };
	symInfo.SizeOfStruct = sizeof(symInfo);
	err = SymFromName(remoteProcessHandle, "getNum", &symInfo);
	check(err);

	void* func2hook = (void*)symInfo.Address;

	//next step is to write the payload function to the victim process' memory
	void* payloadAddrInRemoteProcess = AllocPageInTargetProcess(remoteProcessHandle);
	check(payloadAddrInRemoteProcess);
	err = WriteProcessMemory(remoteProcessHandle, payloadAddrInRemoteProcess, hookPayload, sizeof(hookPayload), nullptr);
	check(err);

	void* hookJumpTarget = payloadAddrInRemoteProcess;

	//it's possible for functions to be located farther than a 32 bit jump away from one
	//another in a 64 bit program, (but there's no 64 bit relative jump instruction), so
	//if the victim process is 64 bit, we need to write an absolute jump instruction somewhere
	//close to func2hook. The E9 jump that gets installed in func2hook will jump to these
	//instructions, which will then do a 64 bit absolute jump to the payload.
	if (IsProcess64Bit(remoteProcessHandle))
	{
		void* absoluteJumpMemory = AllocatePageNearAddressRemote(remoteProcessHandle, func2hook);
		check(absoluteJumpMemory != nullptr);
		WriteAbsoluteJump(remoteProcessHandle, absoluteJumpMemory, payloadAddrInRemoteProcess);
		hookJumpTarget = absoluteJumpMemory;
	}

	//finally, write the actual "hook" into the target function. On 32 bit
	//this will jump directly to the payload, on 64 bit, it jumps to the 
	//absolute jump that we made above, which jumps to the payload
	WriteRelativeJump(remoteProcessHandle, func2hook, hookJumpTarget);
	return 0;
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
