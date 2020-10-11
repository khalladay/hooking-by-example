# Hooking By Example
A series of increasingly complex programs demonstrating function hooking on 64 bit Windows. 

I wrote these programs while teaching myself how function hooking worked. Along the way I figured that they may be helpful for other folks trying to do the same thing. They are intended to be looked at in order. The first time a function is used in a program, it will be included in the .cpp file for that specific example program, with it's name prefixed by an underscore. Any subsequent examples that use the same function will use the copy of that function included in hooking_common.h, to minimize code duplication and keep the later example programs small enough to still be easily readable. 

At runtime, some projects may rely on other projects being built (injecting a dll requires that dll has been built), or running at the same time (hooking a target program requires it be already running).  

# Building
All examples were built using Visual Studio 2019 (v142) with Windows SDK 10.0.17763.0. 
I don't think there's anything here that's VS or SDK version dependent, but I'm listing it here just in case. There are almost certainly some things that are MSVC specific. 

# Contents
The examples are divided into two categories: those that use trampolines, and those that don't. The non-trampoline examples exist solely to demonstrate redirecting program flow from one function to another in different situations. Building trampolines is complicated, and when I was trying to figure out how function hooking worked, it was immensely helpful to start out by building the non-trampoline examples first. 

## Terminology
While there doesn't appear to be much in the way of standard terminology for function hooking techniques, the code (and readmes) in this repository use the following terms:
* Target Function: The function being hooked
* Payload Function: The function which will be called instead of the target function once the hook is installed
* Relay Function: A function containing a 64 bit absolute jump instruction, used to redirect program flow from the target to the payload in 64 bit applications
* Trampoline Function: A function, called by the Payload function, that executes the logic tha the target function contained BEFORE any hooks were installed

## <a name="Non-Trampoline Examples"></a> Non-Trampoline Examples

### [01 - Hook Free Function (x86)]()
A small example of overwriting the starting bytes of a function with a jump instruction that redirects program flow to a different function within the same program. Since there is no trampoline being constructed, this operation is destructive, and the original function is no longer callable. This is the only 32 bit example in the repository. 

### [02 - Hook Free Function (x64)]()
The 64 bit version of the previous example. In 64 bit applications, functions can be located far enough away in memory to not be reachable via a 32 bit relative jump instruction. Since there is no 64 bit relative jump instruction, this program first creates a "relay" function, which contains bytes for an absolute jmp instruction that can reach anywhere in memory (and jumps to the payload func). The 32 bit jump that gets installed in the target function jumps to this relay function, instead of immediately to the payload. 

### [03 - Hook Member Function]()
Provides an example of using the techniques from the previous project to hook a member function, rather than a free function.

### [04 - Hook Virtual Function]()
Slightly different from the previous examples, this program shows how to install a hook into a virtual member function by getting the address of that function through an object's vtable. No other examples deal with virtual functions, but I thought it was interesting enough to include here. 

# References

http://jbremer.org/x86-api-hooking-demystified/#ah-introduction
https://guidedhacking.com/threads/code-detouring-hooking-guide.14185/
https://easyhook.github.io/tutorials/nativeremotehook.html
http://sandsprite.com/blogs/index.php?uid=7&pid=232&year=2012
https://www.ragestorm.net/blogs/?p=107
https://devblogs.microsoft.com/oldnewthing/20170120-00/?p=95225 // -> dll locations and ASLR
https://security.stackexchange.com/questions/18556/how-do-aslr-and-dep-work
https://www.blackhat.com/docs/us-16/materials/us-16-Yavo-Captain-Hook-Pirating-AVs-To-Bypass-Exploit-Mitigations.pdf
https://www.malwaretech.com/2015/01/inline-hooking-for-programmers-part-1.html
https://nagareshwar.securityxploded.com/2014/03/20/code-injection-and-api-hooking-techniques/
https://blog.nettitude.com/uk/windows-inline-function-hooking