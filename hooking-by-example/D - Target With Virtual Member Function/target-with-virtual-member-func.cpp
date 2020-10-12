#include <stdio.h>
#include <Windows.h>

class BaseNum
{
public:
	virtual int getNum() { return 0; }
};

class ChildNumA : public BaseNum
{
public:
	ChildNumA(int n) : _num(n) {}
	virtual __declspec(noinline) int getNum() override {
		return _num;
	}
private:
	int _num;
};

class ChildNumB : public BaseNum
{
public:
	ChildNumB(int n) : _num(n) {}
	virtual __declspec(noinline) int getNum() override {
		return _num + 5;
	}

private:
	int _num;
};

int main()
{
	ChildNumA a(1);
	ChildNumB b(5);

	while (1)
	{
		printf("%i %i\n", a.getNum(), b.getNum());
		Sleep(2000);
	}
	return 0;
}