#ifndef READ_CONFIG_H
#define READ_CONFIG_H

#include <windows.h>
#include <list>
#include <string>
#include "hook_funcs.h"

typedef struct {
    const char *hook_dll;
    std::list<hook_item_t> hook_list;
} hook_dll_t;

extern std::list<hook_dll_t> g_hook_list;
extern time_t g_setup_time;

void read_config(void *module);

#endif
