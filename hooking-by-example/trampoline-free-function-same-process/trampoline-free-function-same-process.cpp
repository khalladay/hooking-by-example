//this program is meant as the simplest possible example of what a trampoline is
//and how creating one works. In order to maintain that simplicity, it hard codes
//assumptions about what the assembly instructions for PrintColorName() are. These
//assumptions may not hold if this program is compiled on a different version of the
//windows toolchain, or windows SDK. 

//notes: definitely no incremental linking for this

#include "..\hooking_common.h"
#include <intrin.h>

#if _WIN64

struct Color
{
	float r;
	float g;
	float b;
};

//since this example is hardcoding the bytes stolen by the hook installed in PrintColorName.
//as such, we won't optimmize it so that the asm is the same in Debug and Release

//when compiled in Debug on v142, Windows SDK 10.0.17763.0
//the first 5 bytes of this function belong to a single instruction
// 48 89 4C 24 08       mov         qword ptr[rsp + 8], rcx
#pragma optimize("", off)
__declspec(noinline) void PrintColorName(Color* color)
{
	Color& c = *color;
	if (c.r == c.g && c.r == c.b && c.r == 1.0f) printf("White\n");
	else if (c.r + c.g + c.b == 0.0f) printf("Black\n");
	else if (c.r == c.g && c.r == c.b) printf("Grey\n");
	else if (c.r > c.g && c.r > c.b) printf("Red\n");
	else if (c.g > c.r && c.g > c.b) printf("Green\n");
	else if (c.b > c.r && c.b > c.g) printf("Blue\n");
	else printf("Something Funky\n");
}
#pragma optimize("", on)

void(*PrintColorNameTrampoline)(Color*);
__declspec(noinline) void HookPayload(Color* color)
{
	color->r = 1.0f;
	color->g = 0.0f;
	color->b = 1.0f;
	PrintColorNameTrampoline(color);
}

void WriteTrampoline(void* dst, void* payloadFuncAddr, void* func2hook, uint8_t* stolenBytes, uint32_t numStolenBytes)
{

	//the trampoline consists of the stolen bytes from the target function, following by a jump back
	//to the target function + 5 bytes, in order to continue the execution of that function. This continues like
	//a normal function call
	void* trampolineJumpTarget = ((uint8_t*)func2hook + 5);

	uint8_t* dstIter = (uint8_t*)dst;
	memcpy(dstIter, stolenBytes, numStolenBytes);
	dstIter += numStolenBytes;
	dstIter += WriteAbsoluteJump64(dstIter, trampolineJumpTarget);
}


int main()
{
	void(*func2hook)(Color*) = PrintColorName;
	void(*payloadFunc)(Color*) = HookPayload;

	DWORD oldProtect;
	bool err = VirtualProtect(func2hook, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(err);

	uint8_t stolenBytes[5];
	memcpy(stolenBytes, func2hook, sizeof(stolenBytes));

	void* trampolineMemory = AllocatePageNearAddress(func2hook);
	PrintColorNameTrampoline = (void(*)(Color*))trampolineMemory;
	WriteTrampoline(trampolineMemory, HookPayload, func2hook, stolenBytes, sizeof(stolenBytes));

	WriteRelativeJump(func2hook, payloadFunc);

	while (1)
	{
		Color c;
		c.r = rand();
		c.g = rand();
		c.b = rand();
		PrintColorName(&c);
		Sleep(500);
	}
}


#else
int main() { printf("Program is intended to always be compiled as 64 bit\n"); }
#endif