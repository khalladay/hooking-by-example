//This file shows how to install a (destructive) inline hook
//into a free function that is part of the same program. "Destructive" 
//in this case just means that the hook payload does not contain a trampoline, 
//so after the hook is installed, the original function is no longer callable.
#include <stdio.h>
#include <Windows.h>
#include <memoryapi.h>
#include <stdint.h>

//this example will crash if built as a 32 bit program. It's totally possible
//to make it work in both 32/64 bits, but in the interest of simplicity, I'm not going to.
static_assert(sizeof(void*) == 8, "This must be built as a 64 bit program");

#define check(expr) if (!(expr)){ DebugBreak(); exit(-1); }

//the target and palyoad functions in this example are so small/trivial that
//enabling optimizations for them breaks this tiny example program
#pragma optimize( "", off )
int getNum()
{
	return 99;
}

int hookPayload()
{
	return 1;
}
#pragma optimize( "", on )

void* AllocatePageNearAddress(void* targetAddr)
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

int main()
{
	printf("Before Hook, getNum() returns %i\n", getNum());

	//since a 64 bit program can have functions located too far away to reach via a 32 bit jump,
	//hooking in 64 bit programs is usually done as two jumps. The first jump is done via a 32
	//bit relative jump (and is installed in the target program). This jump goes from the target
	//program, to a chunk of memory that contains instructions for a 64 bit absolute jump to the 
	//actual payload. 

	DWORD oldProtect;
	BOOL success = VirtualProtect(getNum, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(success);

	void* absoluteJumpMemory = AllocatePageNearAddress(getNum);
	check(absoluteJumpMemory);

	//this writes the absolute jump instructions into the memory allocated near the target
	//the E9 jump installed in the target function (GetNum) will jump to here
	uint8_t absJumpInstructions[] = { 0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //mov 64 bit value into rax
											0xFF, 0xE0 }; //jmp rax

	uint64_t payloadFuncAddr = (uint64_t)hookPayload;
	memcpy(&absJumpInstructions[2], &payloadFuncAddr, sizeof(uint64_t));
	memcpy(absoluteJumpMemory, absJumpInstructions, sizeof(absJumpInstructions));

	//finally, we install the E9 jump into GetNum

	//32 bit relative jump opcode is E9, takes 1 32 bit operand for jump offset
	char jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

	//to fill out the last 4 bytes of jmpInstruction, we need the offset between 
	//the payload function and the instruction immediately AFTER the jmp instruction
	const int relAddr = (int)absoluteJumpMemory - ((int)getNum + sizeof(jmpInstruction));
	memcpy(jmpInstruction + 1, &relAddr, 4);
	memcpy(getNum, jmpInstruction, sizeof(jmpInstruction));

	printf("After Hook, getNum() returns %i\n", getNum());

	return 0;
}