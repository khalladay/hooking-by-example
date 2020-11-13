//This file shows how to install a (destructive) function hook
//into a free function that is part of the same program. "Destructive" 
//in this case just means that the hook payload does not contain a trampoline, 
//so after the hook is installed, the original function is no longer callable.

//This example is only valid when built in 64 bits, and though it will work with
//incremental linking enabled, stepping through code makes more sense with that turned off
#include <stdio.h>
#include <Windows.h>
#include <memoryapi.h>
#include <stdint.h>

#if _WIN64
#define check(expr) if (!(expr)){ DebugBreak(); exit(-1); }

//the target and palyoad functions in this example are so small/trivial that
//enabling optimizations for them breaks this tiny example program, since we need
//at least 5 bytes of instructions
#pragma optimize( "", off )
int GetNum()
{
	return 99;
}

int HookPayload()
{
	return 1;
}
#pragma optimize( "", on )

//allocates memory close enough to the provided targetAddr argument to be reachable
//from the targetAddr by a 32 bit jump instruction
void* _AllocatePageNearAddress(void* targetAddr)
{
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
		uint64_t lowAddr = startPage - byteOffset;

		bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

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

uint32_t _WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo)
{
	//this writes the absolute jump instructions into the memory allocated near the target
	//the E9 jump installed in the target function (GetNum) will jump to here

	//r10 is chosen here because it's a volatile register according to the windows x64 calling convention, 
	//but is not used for return values (like rax) or function arguments (like rcx, rdx, r8, r9)
	uint8_t absJumpInstructions[] = { 0x49, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //mov 64 bit value into r10
										0x41, 0xFF, 0xE2 }; //jmp r10

	uint64_t addrToJumpTo64 = (uint64_t)addrToJumpTo;
	memcpy(&absJumpInstructions[2], &addrToJumpTo64, sizeof(addrToJumpTo64));
	memcpy(absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions));
	return sizeof(absJumpInstructions);
}

int main()
{
	printf("Before Hook, GetNum() returns %i\n", GetNum());

	//since a 64 bit program can have functions located too far away to reach via a 32 bit jump,
	//hooking in 64 bit programs is usually done as two jumps. The first jump is done via a 32
	//bit relative jump (and is installed in the target function). This jump goes from the target
	//program, to a "relay" function, which contains instructions for a 64 bit absolute jump to the 
	//actual payload. 	
	void* relayFuncMemory = _AllocatePageNearAddress(GetNum);
	check(relayFuncMemory);
	_WriteAbsoluteJump64(relayFuncMemory, HookPayload); //write relay func instructions

	//now that the relay function is built, we need to install the E9 jump into the target func,
	//this will jump to the relay function
	DWORD oldProtect;
	BOOL success = VirtualProtect(GetNum, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(success);

	//32 bit relative jump opcode is E9, takes 1 32 bit operand for jump offset
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

	//to fill out the last 4 bytes of jmpInstruction, we need the offset between 
	//the relay function and the instruction immediately AFTER the jmp instruction
	const uint64_t relAddr = (uint64_t)relayFuncMemory - ((uint64_t)GetNum + sizeof(jmpInstruction));
	memcpy(jmpInstruction + 1, &relAddr, 4);

	//install the hook
	memcpy(GetNum, jmpInstruction, sizeof(jmpInstruction));

	printf("After Hook, GetNum() returns %i\n", GetNum());

	return 0;
}
#else
int main()
{
	printf("Example is only valid when compiled as 64 bit\n");
	return 0;
}
#endif