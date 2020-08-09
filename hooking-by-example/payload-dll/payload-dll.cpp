#include "payload-dll.h"

int __fastcall getNum(void* thisPtr)
{
	int* privateData = (int*)thisPtr + 1;
	return *privateData + 100;
}