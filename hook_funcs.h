#ifndef HOOK_FUNCS_H
#define HOOK_FUNCS_H

typedef struct {
	const char *dll_name;
	const char *func_name;
    FARPROC real_addr;
    FARPROC agent_addr;
} hook_item_t;

void set_elapsed_time(time_t atime);
hook_item_t *find_supported_hook(const char *dll_name, const char *func_name);

#endif