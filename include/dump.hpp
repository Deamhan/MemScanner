#pragma once

#include <string>
#include "system_defs.hpp"

static const char DumpSignature[] = "MEMDUMP";

const std::wstring ProtToStr(uint32_t prot);

const uint32_t RFlag = 1;
const uint32_t WFlag = 2;
const uint32_t XFlag = 4;

const uint32_t protToFlags(uint32_t prot);

template <class T>
void printMBI(const SystemDefinitions::MEMORY_BASIC_INFORMATION_T<T>& mbi, const wchar_t* offset = L"");
