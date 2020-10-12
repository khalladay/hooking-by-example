#include <stdio.h>
#include <Windows.h>
#include <memoryapi.h>
#include <stdint.h>
#include "..\hooking_common.h"

#if _WIN64
class Num
{
public:
	Num(int n) :_num(n) {}
	
	//can't hook an inlined function...for obvious reasons
	__declspec(noinline) int GetNum() { return _num; }
private:
	int _num;
};

__declspec(noinline) int HookPayload(Num* thisPtr)
{
	//since Num isn't a virtual type, the private data member _num is located at the address of the object
	int* numPtr = (int*)thisPtr;
	return *numPtr + 5;
}

int main()
{
	Num num(3);
	printf("GetNum from object before hook: %i\n", num.GetNum());

	//you can't normally get a function address out of a 
	//pointer to member function, but through judicious amounts
	//of UB, the following works (at least on MSVC)
	//(found this trick in the Microsoft Detours code)
	int (Num:: * memberPtr)() = &Num::GetNum;
	void* memberAddr = *(void**)(&memberPtr);
	
	//write the relay function
	void* relayFunc = AllocatePageNearAddress(memberAddr);
	check(relayFunc);
	WriteAbsoluteJump64(relayFunc, HookPayload);

	//now install the hook in the target function, it will jump to the relay function
	DWORD oldProtect;
	BOOL success = VirtualProtect(memberAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(success);
		
	//32 bit relative jump opcode is E9, takes 1 32 bit operand for jump offset
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

	//to fill out the last 4 bytes of jmpInstruction, we need the offset between 
	//the relay function and the instruction immediately AFTER the jmp instruction we're about to write
	const uint64_t relAddr = (uint64_t)relayFunc - ((uint64_t)memberAddr + sizeof(jmpInstruction));
	memcpy(jmpInstruction + 1, &relAddr, 4);
	memcpy(memberAddr, jmpInstruction, sizeof(jmpInstruction));

	printf("GetNum from object after hook: %i\n", num.GetNum());
}
#else
int main()
{
	printf("Example is only valid when compiled as 64 bit\n");
	return 0;
}
#endif