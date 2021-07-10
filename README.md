# About MemScanner
This small project is a toolkit for detecting memory anomalies (such as injections). The main feature here is ability to process long 64 bit pointers even from 32 bit application (“Heaven’s Gate” trick is used here). Toolkit supports both X86 and X64 operating systems as well as both bitnesses for resulting binaries.

# How to build
To build the project you need to install [CMake](https://cmake.org/download/), [Visual Studio 2015 or newer](https://visualstudio.microsoft.com/ru/downloads/) 
and [uasm](http://www.terraspace.co.uk/uasm.html). Batch file in root of repo builds assembly code, cmake generates project for IDE (and can build solution using it) 
and allows you to test result.

# Supported sustems
Vista and newer system are supported (both X86 and X64), both binary architectures are supported for building the project.
