#pragma once

// idasdk
#include <pro.h>

enum UNIQUE_RESULT
{
    UNIQUE_ERROR = -1,
    UNIQUE_FALSE = 0,
    UNIQUE_TRUE
};

void WindowTest();
void SearchForSigs(const qstring& sig);
UNIQUE_RESULT isUnique(const char* sig);
