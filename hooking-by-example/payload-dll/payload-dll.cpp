#include "payload-dll.h"

//__fastcall is required for getting the thisPtr correctly when hooking
//an x86 member function. It is ignored on x64
int __fastcall getNum(void* thisPtr)
{
	//this payload is used with the demo program "hook-by-rva-with-dll-payload", 
	//which targets "target-with-virtual-member-functions", and is used to hook
	//a vritual function. Since thisPtr points to a virtual object, private data
	//is located after the vtable pointer
	char* privateData = (char*)thisPtr + sizeof(void*); 
	int* intPtr = (int*)privateData;
	return *intPtr + 100;
}