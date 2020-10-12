//This file shows how to install a (destructive) function hook
//into a virtual function that is part of the same program. "Destructive" 
//in this case just means that the hook payload does not contain a trampoline, 
//so after the hook is installed, the original function is no longer callable.

#include <stdio.h>
#include <Windows.h>
#include <memoryapi.h>
#include <stdint.h>
#include "..\hooking_common.h"

#if _WIN64
class BaseNum
{
public:
	virtual int GetNum() { return 2; }
};

class Num : public BaseNum
{
public:
	Num(int n) : _num(n) {}
	__declspec(noinline) virtual int GetNum() { return _num; }
private:
	int _num;
};

__declspec(noinline) int HookPayload(Num* thisPtr)
{
	uint8_t* bytePtr = (uint8_t*)thisPtr;
	bytePtr += sizeof(uint64_t); //get the first data member after the vtable ptr
	int* intPtr = (int*)bytePtr;
	return *(intPtr)+5;
}

int main()
{
	Num num(3);
	printf("GetNum from object num before hook: %i\n", num.GetNum());

	uint64_t* vtablePtr = (uint64_t*)&num;
	uint64_t* vtable = (uint64_t*)*vtablePtr;
	uint64_t* funcPtr = (uint64_t*)(vtable[0]); //first function in vtable is just the vtable ptr

	DWORD oldProtect;
	BOOL success = VirtualProtect(funcPtr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(success);

	void* relayFunc = AllocatePageNearAddress(funcPtr);
	check(relayFunc);
	WriteAbsoluteJump64(relayFunc, HookPayload);

	//32 bit relative jump opcode is E9, takes 1 32 bit operand for jump offset
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

	//to fill out the last 4 bytes of jmpInstruction, we need the offset between 
	//the payload function and the instruction immediately AFTER the jmp instruction
	const uint64_t relAddr = (uint64_t)relayFunc - ((uint64_t)funcPtr + sizeof(jmpInstruction));
	memcpy(jmpInstruction + 1, &relAddr, 4);
	memcpy(funcPtr, jmpInstruction, sizeof(jmpInstruction));

	printf("GetNum from object num after hook: %i\n", num.GetNum());
}
#else
int main()
{
	printf("Example is only valid when compiled as 64 bit\n");
	return 0;
}
#endif 