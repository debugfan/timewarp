// HookIAT.cpp : Defines the entry point for the console application.
//

#include "HookIAT.h"
#include <stdio.h>
#include <windows.h>

#ifndef MakePtr
#define MakePtr(cast, ptr, addValue) ((cast)((DWORD)(ptr)+(DWORD)(addValue)))
#endif

BOOL HookIAT(const char *pszMainModule, const char *pszModule, PDWORD pOldFunct, PDWORD pNewFunct)
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntheader;
    PIMAGE_IMPORT_DESCRIPTOR ImportDesc;
    PIMAGE_THUNK_DATA pThunk;

    BOOL flDone = FALSE;
    
    dosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(pszMainModule);
    if(dosHeader == NULL)
    {
        return FALSE;
    }

    if(dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
    {
        ntheader = MakePtr(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);
        if ( ntheader->Signature != IMAGE_NT_SIGNATURE ) 
        {
            return FALSE;
        }
        else 
        {
            ImportDesc = MakePtr(PIMAGE_IMPORT_DESCRIPTOR, 
                dosHeader,
                ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
            if ( ImportDesc == (PIMAGE_IMPORT_DESCRIPTOR)ntheader) 
            {
                return FALSE;
            }
            else 
            {
                PIMAGE_IMPORT_DESCRIPTOR ImportDescItr;
                DWORD flOldProtect;
                DWORD flNewProtect;
                DWORD flDontCare;
                PIMAGE_THUNK_DATA pIteratingThunk;
                unsigned cFuncs;
                              
                for (ImportDescItr = ImportDesc; ImportDescItr->Name; ImportDescItr++)
                {
                    PSTR pszModName = MakePtr(PSTR, dosHeader, ImportDescItr->Name);
                    if (lstrcmpi(pszModName, pszModule) == 0)
                    {
                        break;
                    }
                }
                
                pIteratingThunk = pThunk = MakePtr(PIMAGE_THUNK_DATA, dosHeader, ImportDescItr->FirstThunk);
                
                cFuncs = 0;
                while ( pIteratingThunk->u1.Function )
                {
                    cFuncs++;
                    pIteratingThunk++;
                }
                
                flNewProtect = PAGE_EXECUTE_READWRITE;

                if (!VirtualProtect(pThunk, sizeof(PVOID) * cFuncs, flNewProtect, &flOldProtect)) 
                {
                    return FALSE;
                }
                
                for (pIteratingThunk = pThunk; pIteratingThunk->u1.Function; pIteratingThunk++)
                {
                    if(pIteratingThunk->u1.Function == (DWORD *)pOldFunct)
                    {
                        pIteratingThunk->u1.Function = (DWORD *)pNewFunct;
                        flDone = TRUE;
                        break;
                    }
                }
                
                if (!VirtualProtect(pThunk, sizeof(PVOID) * cFuncs, flOldProtect, &flDontCare))
                {
                    return FALSE;
                }
            }
        }
    }

    if(flDone == FALSE)
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

