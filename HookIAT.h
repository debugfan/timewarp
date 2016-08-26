#ifndef HOOK_IAT_H
#define HOOK_IAT_H

#include <Windows.h>

BOOL HookIAT(const char *pszMainModule, const char *pszModule, PDWORD pOldFunct, PDWORD pNewFunct);

#define UnhookIAT(x, y, z, w) HookIAT(x, y, w, z)

#endif