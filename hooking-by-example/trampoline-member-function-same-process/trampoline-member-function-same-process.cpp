#include "..\hooking_common.h"


class Wall
{
public:
	int CountBottlesOnWall()
	{
		printf("%i bottles of beer on the wall! %i bottles of beer!\n", _numBottles, _numBottles);
		return _numBottles;
	}
	void __declspec(noinline) TakeOneDownAndPassItAround()
	{
		_numBottles--;
		printf("Take one down, pass it around! %i bottles of beer on the wall!\n\n", _numBottles);
	}
private:
	int _numBottles = 99;
};



int main()
{
	//you can't normally get a function address out of a 
	//pointer to member function, but through judicious amounts
	//of UB, the following works (at least on MSVC)
	void (Wall:: * func2hook)() = &Wall::TakeOneDownAndPassItAround;
	void* memberAddr = *(void**)(&func2hook);

	DWORD oldProtect;
	BOOL success = VirtualProtect(memberAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(success);

	void* absoluteJumpMemory = AllocatePageNearAddress(memberAddr);
	check(absoluteJumpMemory);





}