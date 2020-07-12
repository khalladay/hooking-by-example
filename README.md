# Hooking By Example
A collection of example projects which demonstrate hooking techniques.

The code for each vs project in the solution is entirely self contained. At runtime, some projects may rely on other projects being built, or running at the same time. 

## Building
All examples were built using Visual Studio 2019 (v142) with Windows SDK 10.0.17763.0. 
I don't think there's anything here that's VS or SDK version dependent, but I'm listing it here just in case. 

## Contents
Since many of these examples involve multiple projects (either for target applications, or for dlls to inject), they are grouped by numbers. Projects that share a prefix number interact with one another (ie: 02a loads the dll 02b). All projects that belong to a certain group are listed below.

#### 01 - Basic 32 Bit Hook
*Projects:* 01-basic-32Bit-inline-hook

The 01-basic-32Bit-inline-hook project is the simplest possible example of an inline function hook that I could think of. It's a 32 bit project that installs a hook (via a relative jmp) into one of its own functions, and uses that hook to redirect program flow to another function compiled into the project. 

#### 02 - Basic 64 Bit Hook
*Projects:* 02a-basic-64bit-inline-hook, 02b-basic-64bit-inline-hook-dll

02a-basic-64bit-inline-hook is the simplest 64 bit compatible hooking program I can think of. It finds a memory region near the function that it wants to hook and writes instructions for an absolute 64 bit jump into that near memory region. Then, it installs a relative jump in the target function to this set of absolute jump instructions, which finally route program flow to the hook payload. In this case, the hook payload function is loaded as a DLL (02b-basic-64bit-inline-hook-dll), which allows the project to ensure that the payload function is always too far from the target function for a relative jump to be able to reach it directly. 

#### 03 - Hook Another Process
*Projects:* 03a-hook-other-process-targetapp, 03b-hook-via-writeprocessmemory, 03c-hook-via-dll-injection, 03d-hook-via-dll-injection-payload

These projects demonstrate the basics of installing a hook into a different process. 03a-hook-other-process-targetapp is a simple app designed to be hooked, while the remainder of the projects in this category show off two different ways to install a hook into that target app. 


#### 04 - Hook An Imported Function
*Projects:* 04a-hook-imported-function, 04b-hook-payload-messagebox, 04c-hook-payload-log-args

The 04 projects demonstrate how to hook a function that a target process has loaded from a dll. This group of projects involves a general purpose hooking program (04a-hook-imported-function) which can be used to install a hook for any imported function in a target process. The remainder of the 04 projects are two dlls that contain payloads that can be used in conjuntion with 04a to hook the CreateBrushIndirect function in MSPaint (as a proof of concept). 