#pragma once

#include "misc.h"

// idasdk
#include <expr.hpp>

void GenerateIDA();
void GenerateCode();
void CreateIDA();
void CreateCode();
bool AutoGenerate(ea_t addr, qstring& outSig, bool showError = false);
bool AddOneInsToSig(qstring& sig, ea_t& addr);
void AddInsToSig(insn_t* ins, qstring& sig);
bool isWildcard(insn_t* ins);
int OpcodeSize(insn_t* ins, unsigned int& outSize);
void AddBytesToSig(qstring& sig, ea_t addr, uint16 size);
void AddWildcardsToSig(qstring& sig, uint16 size);
