#pragma once

#include <loader.hpp>

void ShowCodeWindow(const qstring* sigIDA = nullptr);
void ShowIDAWindow(const qstring* sigIDA = nullptr);
bool isUnique(const qstring& sig);
void SearchForSigs(const qstring& sig);
