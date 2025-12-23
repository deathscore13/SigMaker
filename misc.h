#pragma once

struct Settings_t
{
    ushort dataType = 0;

    // sourcemod compatibility
    // https://github.com/alliedmodders/sourcemod/blob/1.10-dev/tools/gdc/MemoryUtils.cpp#L98
    char wildcard = '\x2A';

    void Save();
    void Load();
};

extern Settings_t Settings;

// idasdk
#include <pro.h>

void Stage(const char* text);
bool SigRange(qstring& outSig);
