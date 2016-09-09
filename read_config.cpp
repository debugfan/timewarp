#include "read_config.h"
#include <Windows.h>
#include <string>
#include "debug_log.h"
#include "xml_common.h"
#include <time.h>

std::list<hook_dll_t> g_hook_list;
time_t g_setup_time = 0;

std::string extract_filepath(const std::string& s)
{
    std::string::size_type pos = 0;
    if((pos = s.find_last_of(":\\/")) != std::string::npos)
    {
        return s.substr(0, pos+1);
    }
    return s;
}

std::string extract_filename(const std::string& s)
{
    std::string::size_type pos = 0;
    if((pos = s.find_last_of(":\\/")) != std::string::npos)
    {
        return s.substr(pos+1);
    }
	else 
	{
		return s;
	}
}

BOOL file_exists (const char *filename) 
{
    FILE *fp;
    if(fp = fopen(filename, "r"))
    {
        fclose(fp);
        return TRUE;
    } 
    else 
    {
        return FALSE;
    }   
}

void parse_hook_item(hook_item_t &hook_item, xmlNodePtr node)
{
	xmlChar *import_name;
	xmlChar *func_name;
    import_name = xmlGetProp(node, (xmlChar *)"import");
	if(import_name != NULL)
	{
		hook_item.dll_name = strdup((char *)import_name);
		xmlFree(import_name);
	}
    func_name = xmlGetProp(node, (xmlChar *)"name");
	if(func_name != NULL)
	{
		hook_item.func_name = strdup((char *)func_name);
		xmlFree(func_name);
	}
}

void parse_hook_dll(hook_dll_t &hook_dll, xmlDoc *doc, xmlNode *node)
{
	xmlNodeSetPtr nodeset;
	xmlXPathObjectPtr pathobj;
    hook_item_t hook_item;

	xmlChar *dll_name = xmlGetProp(node, (xmlChar *)"name");
	if(dll_name != NULL)
	{
		hook_dll.hook_dll = strdup((char *)dll_name);
		xmlFree(dll_name);
	}

	pathobj = getNodeset (doc, node, (xmlChar *)"hook_func");
	if (pathobj) 
	{
		nodeset = pathobj->nodesetval;
		for (int i=0; i < nodeset->nodeNr; i++) 
		{
			parse_hook_item(hook_item, nodeset->nodeTab[i]);
            hook_dll.hook_list.push_back(hook_item);
		}
		xmlXPathFreeObject (pathobj);
	}    
}

time_t transfer_time(const char *human_time)
{
    struct tm tmp;
    memset(&tmp, 0, sizeof(tmp));
    sscanf(human_time, "%d-%d-%d %d:%d:%d", 
        &tmp.tm_year,
        &tmp.tm_mon,
        &tmp.tm_mday,
        &tmp.tm_hour,
        &tmp.tm_min,
        &tmp.tm_sec);
    tmp.tm_year -= 1900;
	tmp.tm_mon -= 1;
    return mktime(&tmp);
}

static HKEY get_rootkey(LPSTR key)
{
    static const CHAR szHKLM[] = "HKLM";
    static const CHAR szHKEY_LOCAL_MACHINE[] = "HKEY_LOCAL_MACHINE";
    static const CHAR szHKCU[] = "HKCU";
    static const CHAR szHKEY_CURRENT_USER[] = "HKEY_CURRENT_USER";
    static const CHAR szHKCR[] = "HKCR";
    static const CHAR szHKEY_CLASSES_ROOT[] = "HKEY_CLASSES_ROOT";
    static const CHAR szHKU[] = "HKU";
    static const CHAR szHKEY_USERS[] = "HKEY_USERS";
    static const CHAR szHKCC[] = "HKCC";
    static const CHAR szHKEY_CURRENT_CONFIG[] = "HKEY_CURRENT_CONFIG";

    if (CompareString(CP_ACP,NORM_IGNORECASE, key, 4, szHKLM, 4) == CSTR_EQUAL ||
        CompareString(CP_ACP,NORM_IGNORECASE, key, 18, szHKEY_LOCAL_MACHINE,18) == CSTR_EQUAL)
        return HKEY_LOCAL_MACHINE;
    else if (CompareString(CP_ACP,NORM_IGNORECASE, key, 4, szHKCU, 4) == CSTR_EQUAL ||
             CompareString(CP_ACP,NORM_IGNORECASE, key, 17, szHKEY_CURRENT_USER,17) == CSTR_EQUAL)
        return HKEY_CURRENT_USER;
    else if (CompareString(CP_ACP,NORM_IGNORECASE, key, 4, szHKCR, 4) == CSTR_EQUAL ||
             CompareString(CP_ACP,NORM_IGNORECASE, key, 17, szHKEY_CLASSES_ROOT,17) == CSTR_EQUAL)
        return HKEY_CLASSES_ROOT;
    else if (CompareString(CP_ACP,NORM_IGNORECASE, key, 3, szHKU, 3) == CSTR_EQUAL ||
             CompareString(CP_ACP,NORM_IGNORECASE, key, 10, szHKEY_USERS,10) == CSTR_EQUAL)
        return HKEY_USERS;
    else if (CompareString(CP_ACP,NORM_IGNORECASE, key, 4, szHKCC, 4) == CSTR_EQUAL ||
             CompareString(CP_ACP,NORM_IGNORECASE, key, 19, szHKEY_CURRENT_CONFIG, 19) == CSTR_EQUAL)
        return HKEY_CURRENT_CONFIG;
    else return NULL;
}

time_t parse_setup_time(xmlNode *node)
{
	xmlChar *type = NULL;
	time_t setup_time = 0;
	type = xmlGetProp(node, (xmlChar *)"type");
	if(type == NULL || 0 == strcmp((char *)type, "assign")) 
	{
		xmlChar *content = xmlNodeGetContent(node);
		if(content != NULL)
		{
			setup_time = transfer_time((char *)content);
			xmlFree(content);
		}
	}
	else if(0 == strcmp((char *)type, "registry"))
	{
		HKEY hKey;
		DWORD stored_value;
		DWORD value_size;

		xmlChar *root_key = xmlGetProp(node, (xmlChar *)"root");
		xmlChar *sub_key = xmlGetProp(node, (xmlChar *)"key");
		xmlChar *value_name = xmlGetProp(node, (xmlChar *)"value_name");
    
        if (ERROR_SUCCESS == RegOpenKeyExA(get_rootkey((char *)root_key),
            (char *)sub_key,
            0,
            KEY_ALL_ACCESS,
            &hKey))
        {
			value_size = sizeof(stored_value);
			if (ERROR_SUCCESS == RegQueryValueExA(hKey,
				(char *)value_name,
				NULL,
				NULL,
				(LPBYTE)&stored_value,
				&value_size))
			{
				setup_time = stored_value;
			}
			else
			{
				log_error(("RegQueryValueExA failed. error code: %d\n", GetLastError()));
			}

			RegCloseKey(hKey);
        }
		else
		{
			log_error(("RegOpenKeyExA failed. error code: %d\n", GetLastError()));
		}

		if(root_key != NULL)
		{
			xmlFree(root_key);
		}
		if(sub_key != NULL)
		{
			xmlFree(sub_key);
		}
		if(value_name != NULL)
		{
			xmlFree(value_name);
		}
	}

	if(type != NULL)
	{
		xmlFree(type);
	}

	return setup_time;
}

void read_xml_config(const char *xml_file)
{
	xmlDocPtr doc;
	xmlNodeSetPtr nodeset;
	xmlXPathObjectPtr pathobj;
    
	xmlSetGenericErrorFunc(NULL, xmlGenericErrorHandler);

	doc = getDoc(xml_file);
	if(doc != NULL)
	{
		pathobj = getNodeset (doc, NULL, (xmlChar *)"/config/hook_dll");
		if (pathobj) 
		{
			nodeset = pathobj->nodesetval;
			for (int i=0; i < nodeset->nodeNr; i++) 
			{
				hook_dll_t hook_dll;
				parse_hook_dll(hook_dll, doc, nodeset->nodeTab[i]);
				g_hook_list.push_back(hook_dll);
			}
			xmlXPathFreeObject (pathobj);
		}

		pathobj = getNodeset (doc, NULL, (xmlChar *)"/config/setup_time");
		if (pathobj) 
		{
			nodeset = pathobj->nodesetval;
			for (int i = 0; i < nodeset->nodeNr; i++) 
			{
				time_t setup_time = parse_setup_time(nodeset->nodeTab[i]);
				if(setup_time != 0)
				{
					g_setup_time = setup_time;
					break;
				}
			}
			xmlXPathFreeObject (pathobj);
		}
		xmlFreeDoc(doc);
	}

	return;
}

void write_setup_time(time_t setup_time, FILE *fp)
{
    struct tm *tmp_tm;
    char time_str[50];
    tmp_tm = gmtime(&setup_time);
    sprintf(time_str, "%04d-%02d-%02d %02d:%02d:%02d",
        tmp_tm->tm_year + 1900,
        tmp_tm->tm_mon + 1,
        tmp_tm->tm_mday,
        tmp_tm->tm_hour,
        tmp_tm->tm_min,
        tmp_tm->tm_sec);
    fputs("<setup_time>", fp);
    fputs(time_str, fp);
    fputs("</setup_time>\n", fp);
}

void write_hook_dll(const char *filename, FILE *fp)
{
	char buf[512];
	sprintf(buf, "<hook_dll name=\"%s\">\n", filename);
    fputs(buf, fp);
    fputs("    <hook_func name=\"GetSystemTimeAsFileTime\" import=\"Kernel32.dll\"/>\n", fp);
    fputs("</hook_dll>\n", fp);
}

void write_config_file(const char *filename, const char *hook_dll, time_t setup_time)
{
    FILE *fp = fopen(filename, "w");
    if (fp != NULL)
    {
        fputs("<config>\n", fp);
        write_setup_time(setup_time, fp);
        write_hook_dll(hook_dll, fp);
        fputs("</config>\n", fp);
        fclose(fp);
    }
}

void read_config(void *module)
{
    char mod_fullpath[MAX_PATH];
	char config_path[MAX_PATH];
    GetModuleFileName((HMODULE)module, mod_fullpath, sizeof(mod_fullpath));
    strcpy(config_path, extract_filepath(mod_fullpath).c_str());
    strcat(config_path, "config.xml");
    log_info(("module file path: %s, xml config path: %s.\n",
		mod_fullpath, 
		config_path));
    if(!file_exists(config_path))
    {
		char app_fullpath[MAX_PATH];
		char app_filename[MAX_PATH];
		GetModuleFileName(NULL, app_fullpath, sizeof(app_fullpath));
		time_t setup_time = time(NULL);
		strcpy(app_filename, extract_filename(app_fullpath).c_str());
		write_config_file(config_path, app_filename, setup_time);
    }

	read_xml_config(config_path);
}
