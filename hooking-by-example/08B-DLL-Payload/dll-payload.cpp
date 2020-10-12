#include "dll-payload.h"

int GetNum(void* thisPtr)
{
	//this payload is used with the demo program "08 - Hook Other Process By RVA with DLL Payload", 
	//which targets "D - Target With Virtual Member Function", and is used to hook
	//a vritual function. Since thisPtr points to a virtual object, private data
	//is located after the vtable pointer
	char* privateData = (char*)thisPtr + sizeof(void*);
	int* intPtr = (int*)privateData;
	return *intPtr + 100;
}