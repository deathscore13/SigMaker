#pragma once

// idasdk
#include <pro.h>
#include <ua.hpp>

void CreateCode(bool position);
void CreateIDA(bool position);
bool Generate(ea_t addr, qstring& outSig, bool position);

bool AddOneInsToSig(qstring& sig, ea_t& addr);
void AddInsToSig(insn_t* ins, qstring& sig);

void AddBytesToSig(qstring& sig, ea_t addr, uint16 size);
void AddWildcardsToSig(qstring& sig, uint16 size);

bool isWildcard(insn_t* ins);
