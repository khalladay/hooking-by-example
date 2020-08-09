#include <stdio.h>
#include <Windows.h>
#include <memoryapi.h>
#include <stdint.h>

#define check(expr) if (!(expr)){ DebugBreak(); exit(-1); }

#if _WIN64
typedef uint64_t addr_t;
#else 
typedef uint32_t addr_t;
#endif

class Num
{
public:
	Num(int n) :_num(n) {}
	
	//can't hook an inlined function...for obvious reasons
	__declspec(noinline) int getNum() { return _num; }
private:
	int _num;
};

__declspec(noinline) int __fastcall hookPayload(Num* thisPtr)
{
	int* numPtr = (int*)thisPtr;
	return *numPtr + 5;
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

void* WriteAbsoluteJump(void* absJumpMemory)
{
#ifdef _WIN64
	//this writes the absolute jump instructions into the memory allocated near the target
	//the E9 jump installed in the target function (GetNum) will jump to here
	uint8_t absJumpInstructions[] = { 0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //mov 64 bit value into rax
											0xFF, 0xE0 }; //jmp rax

	addr_t payloadFuncAddr = (addr_t)hookPayload;
	memcpy(&absJumpInstructions[2], &payloadFuncAddr, sizeof(addr_t));
	memcpy(absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions));
	return absJumpMemory;
#else
	return nullptr;
#endif
}

int main()
{
	Num num(3);
	printf("GetNum from object num: %i\n", num.getNum());

	//you can't normally get a function address out of a 
	//pointer to member function, but through judicious amounts
	//of UB, the following works (at least on MSVC)
	int (Num:: * memberPtr)() = &Num::getNum;
	void* memberAddr = *(void**)(&memberPtr);

	DWORD oldProtect;
	BOOL success = VirtualProtect(memberAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(success);

	void* absoluteJumpMemory = AllocatePageNearAddress(memberAddr);
	check(absoluteJumpMemory);

	void* jumpTarget = WriteAbsoluteJump(absoluteJumpMemory);
	if (!jumpTarget) jumpTarget = hookPayload;

	//32 bit relative jump opcode is E9, takes 1 32 bit operand for jump offset
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

	//to fill out the last 4 bytes of jmpInstruction, we need the offset between 
	//the payload function and the instruction immediately AFTER the jmp instruction
	const addr_t relAddr = (addr_t)jumpTarget- ((addr_t)memberAddr + sizeof(jmpInstruction));
	memcpy(jmpInstruction + 1, &relAddr, 4);
	memcpy(memberAddr, jmpInstruction, sizeof(jmpInstruction));

	addr_t relAddrToRedirector = (addr_t)jumpTarget- ((addr_t)memberAddr + 5);
	memcpy(jmpInstruction + 1, &relAddrToRedirector, 4);
	memcpy(memberAddr, jmpInstruction, sizeof(jmpInstruction));
	printf("GetNum from object num: %i\n", num.getNum());
}