# Hooking By Example
A series of increasingly complex programs demonstrating function hooking on 64 bit Windows. 

I wrote these programs while teaching myself how function hooking works. They may be helpful for other folks trying to do the same thing (or future me after I forget how all this works again). They are intended to be looked at in order. The first time a function is used in a program, it will be included in the .cpp file for that specific example program, with its name prefixed by an underscore. Any subsequent examples that use the same function will use the copy of that function included in hooking_common.h, to minimize code duplication and keep the later example programs small enough to still be easily readable. 

I've done a bit of work to clean them up, but the later examples are still a bit messy. It's important to note that the final result in this repo isn't enough to write a fully featured hooking library, but it's enough to get started down that path. 

At runtime, some projects may rely on other projects being built (injecting a dll requires that dll has been built), or running at the same time (hooking a target program requires it be already running).  

# Building
All examples were built using Visual Studio 2019 (v142) with Windows SDK 10.0.17763.0. 
I don't think there's anything here that's VS or SDK version dependent, but I'm listing it here just in case. There are almost certainly some things that are MSVC specific. 

Finally, the last trampoline example installs a hook in mspaint. I assume at some point in the future, an update to mspaint will cause this example to break. At the time of writing, the current version of mspaint was 1909 (OS Build 18363.1016). 

# Contents
The examples are divided into two categories: those that use trampolines, and those that don't. The non-trampoline examples exist solely to demonstrate redirecting program flow from one function to another in different situations. Building trampolines is complicated, and when I was trying to figure out how function hooking worked, it was immensely helpful to start out by building the non-trampoline examples first. Additionally, there are 4 "target programs" which are used by examples that want to demonstrate how to install hooks in different (already running) processes. 

Most of these examples leak memory related to the hooks. I don't really care, both because these examples are just to demonstrate a hooking concept, and because these "leaked" allocs need to exist until program termination anyway. 

## Terminology
While there doesn't appear to be much in the way of standard terminology for function hooking techniques, the code (and readmes) in this repository use the following terms:
* Target Function: The function being hooked
* Payload Function: The function which will be called instead of the target function once the hook is installed
* Relay Function: A function containing a 64 bit absolute jump instruction, used to redirect program flow from the target to the payload in 64 bit applications
* Trampoline Function: A function, called by the Payload function, that executes the logic that the target function contained BEFORE any hooks were installed. (this is a simplified explanation)
* Stolen Bytes: the instruction bytes in the target function that are overwritten when a hook is installed in that function

## <a name="Non-Trampoline Examples"></a> Non-Trampoline Examples
Since these examples don't create trampolines when installing their hooks, I think of these functions as demonstrating "destructive" hooking, in that the original function is completely unusable after being hooked. 

### [01 - Hook Free Function (x86)](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/01%20-%20Hook%20Free%20Function%20(x86)/hook-free-function-x86.cpp)
A small example of overwriting the starting bytes of a function with a jump instruction that redirects program flow to a different function within the same program. Since there is no trampoline being constructed, this operation is destructive, and the original function is no longer callable. This is the only 32 bit example in the repository. 

### [02 - Hook Free Function (x64)](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/02%20-%20Hook%20Free%20Function%20(x64)/hook-free-function-x64.cpp)
The 64 bit version of the previous example. In 64 bit applications, functions can be located far enough away in memory to not be reachable via a 32 bit relative jump instruction. Since there is no 64 bit relative jump instruction, this program first creates a "relay" function, which contains bytes for an absolute jmp instruction that can reach anywhere in memory (and jumps to the payload func). The 32 bit jump that gets installed in the target function jumps to this relay function, instead of immediately to the payload. 

### [03 - Hook Member Function](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/03%20-%20Hook%20Member%20Function/hook-member-function.cpp)
Provides an example of using the techniques from the previous project to hook a member function, rather than a free function.

### [04 - Hook Virtual Function](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/04%20-%20Hook%20Virtual%20Function/hook-virtual-function.cpp)
Slightly different from the previous examples, this program shows how to install a hook into a virtual member function by getting the address of that function through an object's vtable. No other examples deal with virtual functions, but I thought it was interesting enough to include here. 

### [05 - Hook Other Process By Symbol Name](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/05%20-%20Hook%20Other%20Process%20By%20Symbol%20Name/hook-process-by-symbol-name.cpp)
The simplest example of installing a hook into another running process. This example uses the DbgHelp library to locate a function in a target processs ([A - Target With Free Function]()) by string name. This is only possible because the target program is built with debug symbols enabled. While simple, this example is a bit longer than previous programs because of the large number of new functions it introduces (for locating and manipulating a remote process). 

### [06 - Hook Func Imported From DLL By Other Process](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/06%20-%20Hook%20Func%20Imported%20From%20DLL%20By%20Other%20Process/hook-func-imported-from-dll-by-process.cpp)
This example shows how to hook a function that another process has imported from a dll. There's some nuance to how to get the address of a dll function in a remote process due to how ASLR works, which is demonstrated here. Otherwise, this example is almost identical to the previous one.

### [07 - Hook Other Process By RVA](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/07%20-%20Hook%20Other%20Process%20By%20RVA/hook-other-process-by-rva.cpp)
This example shows how to install a hook in a function that is not imported by a dll, and which is not in the symbol table (likely because the remote process does not have debug symbols). This means there's no (easy) way to find the target function by string name. Instead, this example assumes that you've used a disassembler like x64dbg to get the relative virtual address (RVA) of the funtion you want to hook. This program uses that RVA to install a hook. 

### [08 - Hook Other Process By RVA with DLL Payload](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/08%20-%20Hook%20Other%20Process%20By%20RVA%20with%20DLL%20Payload/hook-by-rva-with-dll-payload.cpp)
Similar to the above, except this example uses dll injection to install the payload function rather than writing raw machine code bytes. This is much easier to work with, since your payloads can be written in C++ again. The payload for this example is contained in the project [08B-DLL-Payload](https://github.com/khalladay/hooking-by-example/tree/master/hooking-by-example/08B-DLL-Payload). 

## <a name="Trampoline Examples"></a> Trampoline Examples
The following examples install trampolines when hooking, meaning that the program can still execute the logic in the target function after a hook has been installed. Since installing a hook overwrites at least the first 5 bytes in the target function, the instructions contained in these 5 bytes are moved to the trampoline function. Thus, calling the trampoline function effectively executes the original logic of the target function. 

### [09 - Trampoline Free Function In Same Process](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/09%20-%20Trampoline%20Free%20Function%20In%20Same%20Process/trampoline-free-function.cpp)
The trampoline-installing equivalent of example #2. This example is a bit weird because I wanted to demonstrate creating a trampoline without needing to use a disassembly engine. In this case, the target function was created to have a known 5 byte instruction at the beginning, so we can just copy the first five bytes of that function to the trampoline function. This means creating the trampoline is really easy, since we know it's exact size and that it doesn't use any relative addressing that needs to be fixed up. If you were writing a trampoline for a really specific use case, you could probably get away with just doing a variation on this. 

### [10 - Trampoline With Disassembler In Same Process](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/10%20-%20Trampoline%20With%20Disassembler%20In%20Same%20Process/trampoline-with-disasm.cpp)
This example shows a similar scenario to the previous one, except this time I'm using a disassembler ([capstone](http://www.capstone-engine.org/)) to get the bytes we need to steal out of the target function. This allows the hooking code to be used on any function, not just ones that we know are going to be easy cases. There's actually a whole lot going on in this example, because it's jumping from a targetted hook (like the previous one) to building a generic hooking function. The trampoline has to convert relative calls/jumps into instructions that use absolute addresses, which complicates things further. This isn't a 100% polished example of generic hooking either, it will fail with loop instructions, and if you try to hook functions with fewer than 5 bytes of instructions.

### [11 - Trampoline With Thread-Safer Install](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/11%20-%20Trampoline%20With%20Thread-Safer%20Install/trampoline-thread-safe-install.cpp)
Basically the same as the above, except this example includes code to pause all executing threads while it installs a hook. This isn't guaranteed to be threadsafe in all cases, but it's definitely a lot more safe than doing nothing. 

### [12 - Multiple Trampolines, Multiple Hooks](https://github.com/khalladay/hooking-by-example/tree/master/hooking-by-example/12%20-%20Multiple%20Trampolines%2C%20Multiple%20Hooks)
This expands on the hooking/trampoline code used in the previous two examples to support having multiple functions redirect to the same payload, and to allow payload functions to call other functions with hooks installed in them. 

### [13 - Trampoline Imported Func With DLL Injection](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/13%20-%20Trampoline%20Imported%20Func%20With%20DLL%20Injection/trampoline-remote-process-with-dll-injection.cpp)
This is the first trampoline example that installs a hook in a different process (in this case, the target app [B - Target with Free Functions From DLL]()). All the hooking logic is contained in a dll payload [13B - Trampoline Imported Func DLL Payload](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/13B%20-%20Trampoline%20Imported%20Func%20DLL%20Payload/trampoline-imported-func-payload.cpp). There's not much new here, this example just combines the trampoline hooking stuff already done with the previously shown techniques for hooking a function imported from a dll. 

### [14 - Trampoline Hook MSPaint](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/14%20-%20Trampoline%20Hook%20MSPaint/trampoline-hook-mspaint.cpp)
The crown jewel of the repo. This example injects a dll payload ([14B - Trampoline Hook MSPaint Payload](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/14B%20-%20Trampoline%20Hook%20MSPaint%20Payload/trampoline-hook-mspaint-payload.cpp)) into a running instance of mspaint (you have to launch mspaint yourself before running this). The installed hook causes brushes to draw as red, no matter what color you've actually selected in MSPaint. There's honestly nothing here that wasn't shown in the previous example, it's just cool to see this working on a non-contrived program. 

## <a name="Target Programs"></a> Target Programs

### [A - Target With Free Functions](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/A%20-%20Target%20With%20Free%20Functions/target-with-free-function.cpp)
Simple target application that calls a free function in a loop. Compiled with debug information included. 

### [B - Target With Free Function From DLL](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/B%20-%20Target%20With%20Free%20Function%20From%20DLL/target-with-free-function-from-dll.cpp)
Target application that calls a free function that has been imported from a dll ([B2 - GetNum-DLL](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/B2%20-%20GetNum-DLL/GetNum-DLL.cpp)) in a loop. 

### [C - Target With Non-Virtual Member Functions](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/C%20-%20Target%20With%20Non-Virtual%20Member%20Functions/target-with-member-function.cpp)
Target application that calls a non virtual member function in a loop.

### [D - Target With Virtual Member Function](https://github.com/khalladay/hooking-by-example/blob/master/hooking-by-example/D%20-%20Target%20With%20Virtual%20Member%20Function/target-with-virtual-member-func.cpp)
Target application that calls a virtual member function in a loop. 

# References

* https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=vs-2019
* http://jbremer.org/x86-api-hooking-demystified/#ah-introduction
* https://guidedhacking.com/threads/code-detouring-hooking-guide.14185/
* https://easyhook.github.io/tutorials/nativeremotehook.html
* http://sandsprite.com/blogs/index.php?uid=7&pid=232&year=2012
* https://www.ragestorm.net/blogs/?p=107
* https://devblogs.microsoft.com/oldnewthing/20170120-00/?p=95225 
* https://security.stackexchange.com/questions/18556/how-do-aslr-and-dep-work
* https://www.blackhat.com/docs/us-16/materials/us-16-Yavo-Captain-Hook-Pirating-AVs-To-Bypass-Exploit-Mitigations.pdf
* https://www.malwaretech.com/2015/01/inline-hooking-for-programmers-part-1.html
* https://nagareshwar.securityxploded.com/2014/03/20/code-injection-and-api-hooking-techniques/
* https://blog.nettitude.com/uk/windows-inline-function-hooking
* https://www.fireeye.com/blog/threat-research/2020/03/six-facts-about-address-space-layout-randomization-on-windows.html
* http://www.nynaeve.net/?p=192
* https://medium.com/@_sl4v/hooking-is-easy-right-right-fb00de2f2372
* https://github.com/stevemk14ebr/PolyHook
* https://github.com/microsoft/Detours
* https://github.com/TsudaKageyu/minhook
* https://easyhook.github.io/
