//this is a simple program used to test methods for installing 
//a hook in a different process. The idea is for another process to 
//hook the getNum functions of this app, to cause it to output a different
//value to the console from the while loop in main

//I've disabled generating debug info for this program, so there aren't
//symbol names to use to hook into easily. Instead, you need to get the RVA
//for the getNum function from a program like x64dbg, and use that to 
//get the address of the function

#include <stdio.h>
#include <Windows.h>

class Num
{
public:
	Num(int n) : _num(n) {}
	__declspec(noinline) int getNum() 
	{
		return _num;
	}

private:
	int _num;
};

int main()
{
	Num n(0);
	while (1)
	{
		printf("%i\n", n.getNum());
		Sleep(2000);
	}
	return 0;
}