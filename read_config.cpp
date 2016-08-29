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

void parse_iat_hook_item(hook_item_t &hook_item, xmlNodePtr node)
{
    hook_item.dll_name = strdup((char *)xmlGetProp(node, (xmlChar *)"import"));
    hook_item.func_name = strdup((char *)xmlGetProp(node, (xmlChar *)"name"));
}

void parse_hook_dll(hook_dll_t &dll_list, xmlDoc *doc, xmlNode *node)
{
	xmlChar *xpath = (xmlChar*) "hook_func";
	xmlNodeSetPtr nodeset;
	xmlXPathObjectPtr pathobj;
    hook_item_t hook_item;

	pathobj = getNodeset (doc, node, xpath);
	if (pathobj) {
		nodeset = pathobj->nodesetval;
		for (int i=0; i < nodeset->nodeNr; i++) 
		{
			parse_iat_hook_item(hook_item, nodeset->nodeTab[i]);
            dll_list.hook_list.push_back(hook_item);
		}
		xmlXPathFreeObject (pathobj);
	}    
}

void get_hook_list(std::list<hook_dll_t> &dll_list, xmlDoc *doc, xmlNodeSet *nodeset)
{
    hook_dll_t hook_dll;
	for (int i=0; i < nodeset->nodeNr; i++) 
	{
        hook_dll.hook_dll = (char *)xmlGetProp(nodeset->nodeTab[i], (xmlChar *)"name");
		parse_hook_dll(hook_dll, doc, nodeset->nodeTab[i]);
        dll_list.push_back(hook_dll);
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
			get_hook_list(g_hook_list, doc, nodeset);
			xmlXPathFreeObject (pathobj);
		}

		pathobj = getNodeset (doc, NULL, (xmlChar *)"/config/setup_time");
		if (pathobj) 
		{
			nodeset = pathobj->nodesetval;
			for (int i=0; i < nodeset->nodeNr; i++) 
			{
				g_setup_time = transfer_time((char *)xmlNodeGetContent(nodeset->nodeTab[i]));
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
