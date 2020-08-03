#include <stdio.h>

class BaseNum
{
public:
	virtual int getNum() { return 0; }
};

class ChildNumA : public BaseNum
{
public:
	ChildNumA(int n) : _num(n) {}
	virtual int getNum() override {
		return _num;
	}
private:
	int _num;
};

class ChildNumB : public BaseNum
{
public:
	ChildNumB(int n) : _num(n) {}
	virtual int getNum() override final {
		return _num + 5;
	}

private:
	int _num;
};

int main(int argc, const char** argv)
{
	return 0;
}