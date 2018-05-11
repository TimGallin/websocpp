#ifndef WEBSOCMM_HEADER_URI_H
#define WEBSOCMM_HEADER_URI_H
#pragma once

#include <string>

namespace websoc_types
{
    typedef struct uriparts_
    {
        std::string scheme;
        std::string host;
        int port;
        std::string path;
        std::string query;
    } urlparts;

    bool websoc_uri_parse(const std::string &uri, uriparts &parts);
}

#endif
