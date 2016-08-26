#include "xml_common.h"
#pragma comment(lib, "libxml2_a.lib")
#pragma comment(lib, "ws2_32.lib")

void xmlGenericErrorHandler(void *ctx, const char *msg, ...)
{
	char buf[1024];
	va_list arg_ptr;
	va_start(arg_ptr, msg);
	_vsnprintf(buf, sizeof(buf) - 1, msg, arg_ptr);
	va_end(arg_ptr);
	printf("Error: %s\n", buf);
}

xmlDocPtr getDoc(const char *docname) 
{
	xmlDocPtr doc;
	doc = xmlParseFile(docname);
	if (doc == NULL) 
	{
		fprintf(stderr, "Fail to parse file: %s. \n", docname);
		return NULL;
	}

	return doc;
}

xmlXPathObjectPtr getNodeset(xmlDocPtr doc, xmlNodePtr node, xmlChar *xpath)
{
	xmlXPathContextPtr context;
	xmlXPathObjectPtr result;

	context = xmlXPathNewContext(doc);
	if (context == NULL) 
	{
		printf("Error in xmlXPathNewContext\n");
		return NULL;
	}

	if(node != NULL)
	{
		context->node = node;
	}

	result = xmlXPathEvalExpression(xpath, context);

	xmlXPathFreeContext(context);
	if (result == NULL) 
	{
		printf("Error in xmlXPathEvalExpression. xpath: %s\n", (char *)xpath);
		return NULL;
	}

	if(xmlXPathNodeSetIsEmpty(result->nodesetval))
	{
		xmlXPathFreeObject(result);
		printf("NodeSet is empty. xpath: %s\n", (char *)xpath);
		return NULL;
	}

	return result;
}
