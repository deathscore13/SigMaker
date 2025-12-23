#pragma once

// idasdk
#include <pro.h>

void WindowConverter();
bool CodeToIDA(qstring code, const qstring& mask, qstring& outSig);
bool IDAToCode(qstring sig, qstring& outSig, qstring& outMask);
