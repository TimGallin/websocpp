#include "uriparts.h"
#include <algorithm>

/*
RFC6455:https://tools.ietf.org/html/rfc6455#section-3
3.  WebSocket URIs

   This specification defines two URI schemes, using the ABNF syntax
   defined in RFC 5234 [RFC5234], and terminology and ABNF productions
   defined by the URI specification RFC 3986 [RFC3986].

          ws-URI = "ws:" "//" host [ ":" port ] path [ "?" query ]
          wss-URI = "wss:" "//" host [ ":" port ] path [ "?" query ]

          host = <host, defined in [RFC3986], Section 3.2.2>
          port = <port, defined in [RFC3986], Section 3.2.3>
          path = <path-abempty, defined in [RFC3986], Section 3.3>
          query = <query, defined in [RFC3986], Section 3.4>

   The port component is OPTIONAL; the default for "ws" is port 80,
   while the default for "wss" is port 443.

   The URI is called "secure" (and it is said that "the secure flag is
   set") if the scheme component matches "wss" case-insensitively.

   The "resource-name" (also known as /resource name/ in Section 4.1)
   can be constructed by concatenating the following:

   o  "/" if the path component is empty

   o  the path component

   o  "?" if the query component is non-empty

   o  the query component

   Fragment identifiers are meaningless in the context of WebSocket URIs
   and MUST NOT be used on these URIs.  As with any URI scheme, the
   character "#", when not indicating the start of a fragment, MUST be
   escaped as %23.
*/

#define STRCMP_2(x,y1,y2)  \
    x[0]==y1 && x[1]==y2

namespace websoc_types
{
    bool websoc_uri_parse(const std::string &uri, uriparts &parts){
        enum {
            sw_scheme = 0,
            sw_slash,
            sw_host,
            sw_colon,
            sw_port,
            sw_path,
            sw_query
        }state = sw_start;

        std::string::cosnt_iterator ite = uri.cbegin();

        for(ite; ite != uri.cend(); ++ite){
            char ch = *ite;

            switch(state){
                case sw_scheme:
                    if(PRECMP_2(&ch,'/','/') == 0)
                        state = sw_slash;
                        break;
                    
                    parts.scheme.append(1,ch);
                    break;
                
                case sw_slash:
                    if(ch == '/'){
                        state = sw_host;
                    }
                    break;
                
            }
        }

    }
}