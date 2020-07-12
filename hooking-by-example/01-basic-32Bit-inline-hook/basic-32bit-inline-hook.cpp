//This is the simplest possible example of hooking that I could come up with. 
//All it does is overwrite the first 5 bytes of the target function with an unconditional,
//relative jump instruction, forcing execution to jump to the hook function

#include <stdio.h>
#include <Windows.h>
#include <memoryapi.h>
#include <stdint.h>

//This will _probably_ work when compiled as 64 bit, but it isn't guaranteed to, since
//there's no guarantee that our two functions will be placed close enough for a 32 bit relative
//jump instruction to be able to reach one from the other. 
static_assert(INTPTR_MAX == INT32_MAX, "This example needs to be compiled as 32 bit");

#define check(expr) if (!(expr)){ DebugBreak(); exit(-1); }

//we have to disable optimization on these functions, otherwise release builds will just
//optimize calls to them away and replace them with constants
#pragma optimize( "", off )

//this is the function that will get hooked
int getNum()
{
	return 99;
}

//this is where our hook will redirect program flow to
int getNumHook()
{
	return 1;
}

#pragma optimize( "", on )

int main()
{
	printf("Before Hook, getNum() returns %i\n", getNum());

	int32_t RelAddr = (int32_t)getNumHook - ((int32_t)getNum + 5);

	//need to mark the target function as READWRITE so that it can be modified
	DWORD oldProtect;
	BOOL success = VirtualProtect(getNum, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(success);

	//32 bit relative jump opcode is E9, takes 1 32 bit operand for jump offset
	char jmp_instruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };
	memcpy(jmp_instruction + 1, &RelAddr, 4);

	memcpy(getNum, jmp_instruction, sizeof(jmp_instruction));

	printf("After Hook, getNum() returns %i\n", getNum());

	return 0;
}