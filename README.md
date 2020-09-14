# Hooking By Example
A series of increasingly more complex programs demonstrating function hooking on 64 bit Windows. Aside from a single common header file (hooking_common.h), all examples are contained within a single .cpp file. 

I wrote these programs while teaching myself how function hooking worked. Along the way I figured that they may be helpful for other folks trying to do the same thing. 

At runtime, some projects may rely on other projects being built (injecting a dll requires that dll has been built), or running at the same time (hooking a target program requires it be already running).  

# Building
All examples were built using Visual Studio 2019 (v142) with Windows SDK 10.0.17763.0. 
I don't think there's anything here that's VS or SDK version dependent, but I'm listing it here just in case. There are almost certainly some things that are MSVC specific. 

# Contents
The examples are divided into two categories: those that use trampolines, and those that don't. The non-trampoline examples exist solely to demonstrate redirecting program flow from one function to another in different situations. Building trampolines is complicated, and when I was trying to figure out how function hooking worked, it was immensely helpful to start out by building the non-trampoline examples first. 

## Non-Trampoline Examples

### 1 - Hooking a Free Function In 64 Bit Windows

# References