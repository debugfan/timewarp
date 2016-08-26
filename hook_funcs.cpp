#include <windows.h>
#include <time.h>
#include "HookIAT.h"
#include "read_config.h"
#include "debug_log.h"
#include "hook_funcs.h"

unsigned int g_elapsed_time = 0;

#define __in
#define __out
#define __in_out
#define _In_
#define _Out_

void set_elapsed_time(time_t atime)
{
	g_elapsed_time = atime;
}

void (WINAPI *Real_GetSystemTimeAsFileTime)(
                                            _Out_  LPFILETIME lpSystemTimeAsFileTime
                                            ) = GetSystemTimeAsFileTime;

void WINAPI My_GetSystemTimeAsFileTime(
                                       _Out_  LPFILETIME lpSystemTimeAsFileTime
                                       )
{
    ULARGE_INTEGER utime;
    Real_GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
    if(lpSystemTimeAsFileTime != NULL)
    {
        utime.LowPart = lpSystemTimeAsFileTime->dwLowDateTime;
        utime.HighPart = lpSystemTimeAsFileTime->dwHighDateTime;
        utime.QuadPart = utime.QuadPart - UInt32x32To64(10*1000*1000, g_elapsed_time);
        lpSystemTimeAsFileTime->dwLowDateTime = utime.LowPart;
        lpSystemTimeAsFileTime->dwHighDateTime = utime.HighPart;
    }
}

time_t (*real_time)(
                    time_t *timer 
                    ) = time;

time_t my_time (
                time_t *timer 
                )
{
    time_t r;
    if(timer == NULL)
    {
        r = (real_time(timer) - g_elapsed_time);
        log_info(("result: %d\n", r));
        return r;
    }
    else
    {
        real_time(timer);
        *timer = *timer - g_elapsed_time;
        log_info(("result: %d\n", *timer));
        return *timer;
    }
}

hook_item_t hook_table[] = {
    {"Kernel32.dll", 
        "GetSystemTimeAsFileTime", 
        (FARPROC)Real_GetSystemTimeAsFileTime, 
        (FARPROC)My_GetSystemTimeAsFileTime},
	{"msvcrt.dll", 
        "time", 
        (FARPROC)real_time, 
        (FARPROC)my_time}
};

hook_item_t *find_supported_hook(const char *dll_name, const char *func_name)
{
    int i;
    for(i = 0; i < sizeof(hook_table)/sizeof(hook_item_t); i++)
    {
        if(strcmp(dll_name, hook_table[i].dll_name) == 0
            && strcmp(func_name, hook_table[i].func_name) == 0) 
        {
            return &hook_table[i];
        }
    }
    return NULL;
}


