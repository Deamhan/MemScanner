# About Wow64Helper
This is small project is mostly demo of “Heaven’s Gate”: it is used here mostly to process 64 bit pointers from 32 bit application. 
In addition the simple memory scaning tool was added as example (some kinds of injection can be detected).

# How to build
To build the project you need to install [CMake](https://cmake.org/download/), [Visual Studio 2015 or newer](https://visualstudio.microsoft.com/ru/downloads/) 
and [uasm](http://www.terraspace.co.uk/uasm.html). Batch file in root of repo builds assembly code, cmake generates project for IDE (and can build solution using it) 
and allows you to test result.
