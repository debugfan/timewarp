#include <windows.h>
#include <time.h>
#include "HookIAT.h"
#include "read_config.h"
#include "debug_log.h"
#include "hook_funcs.h"

extern "C" __declspec(dllexport) int donothing(int x) 
{
    return 0;
}

time_t caculate_elapsed_time()
{
    time_t cur_time;

    if(g_setup_time == 0)
    {
        return 0;
    }

    cur_time = time(NULL);

    if(cur_time > (time_t)g_setup_time)
    {
        return (cur_time - g_setup_time);
    }
    else
    {
        return 0;
    }
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    std::list<hook_dll_t>::iterator iter;
    if (dwReason == DLL_PROCESS_ATTACH) {
        read_config(hinst);
        Sleep(200);
        set_elapsed_time(caculate_elapsed_time());

        for(iter = g_hook_list.begin();
            iter != g_hook_list.end();
            iter++)
        {
            std::list<hook_item_t>::iterator item_iter;
            for(item_iter = iter->hook_list.begin();
                item_iter != iter->hook_list.end();
                item_iter++)
                {
                    hook_item_t *supported_item = find_supported_hook(item_iter->dll_name, 
						item_iter->func_name);
                    if(supported_item != NULL 
						&& supported_item->real_addr != NULL
						&& supported_item->agent_addr != NULL)
                    {
                        item_iter->real_addr = supported_item->real_addr;
                        item_iter->agent_addr = supported_item->agent_addr;
                        if(FALSE == HookIAT(iter->hook_dll, 
                            item_iter->dll_name,
                            (PDWORD)item_iter->real_addr,
                            (PDWORD)item_iter->agent_addr))
                        {   
                            log_error(("Hook IAT failed"));
                        }
                    }
                }

        }
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        for(iter = g_hook_list.begin();
            iter != g_hook_list.end();
            iter++)
        {
            std::list<hook_item_t>::iterator item_iter;
            for(item_iter = iter->hook_list.begin();
                item_iter != iter->hook_list.end();
                item_iter++)
                {
					if(item_iter->real_addr != NULL
						&& item_iter->agent_addr != NULL)
					{
						if(FALSE == UnhookIAT(iter->hook_dll, 
							item_iter->dll_name,
							(PDWORD)item_iter->real_addr,
							(PDWORD)item_iter->agent_addr))
						{   
							log_error(("Hook IAT failed"));
						}
					}
                }

        }
    }

    return TRUE;
}

