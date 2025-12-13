#pragma once

// idasdk
#include <loader.hpp>

void IDAToCode(const qstring& sig, qstring& outSig, qstring& outMask);
void CodeToIDA(const char* code, const qstring& mask, qstring& outSig);
void CodeToIDAC(const char* code, const qstring& mask, qstring& outSig);
void ShowSigConverter();
