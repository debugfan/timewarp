#ifndef XML_COMMON_H
#define XML_COMMON_H

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>
#include <string>
using std::string;

void xmlGenericErrorHandler(void *ctx, const char *msg, ...);
xmlDocPtr getDoc(const char *docname);
xmlXPathObjectPtr getNodeset(xmlDocPtr doc, xmlNodePtr node, xmlChar *xpath);

#endif