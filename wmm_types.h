#ifndef WEBSOCMM_HEADER_URI_H
#define WEBSOCMM_HEADER_URI_H
#pragma once

#include <string>
#include <stdint.h>

#ifdef WIN
#define INVALID_SOCKETMM INVALID_SOCKET
#else ifdef LINUX
#define INVALID_SOCKETMM -1
#endif

namespace websoc_types
{
typedef struct uriparts_
{
    std::string scheme;
    std::string host;
    std::string port;
    std::string path;
    std::string query;
} urlparts;

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
bool websoc_uri_parse(const std::string &uri, urlparts &parts);

// http://tools.ietf.org/html/rfc6455#section-5.2  Base Framing Protocol
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-------+-+-------------+-------------------------------+
// |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
// |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
// |N|V|V|V|       |S|             |   (if payload len==126/127)   |
// | |1|2|3|       |K|             |                               |
// +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
// |     Extended payload length continued, if payload len == 127  |
// + - - - - - - - - - - - - - - - +-------------------------------+
// |                               |Masking-key, if MASK set to 1  |
// +-------------------------------+-------------------------------+
// | Masking-key (continued)       |          Payload Data         |
// +-------------------------------- - - - - - - - - - - - - - - - +
// :                     Payload Data continued ...                :
// + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
// |                     Payload Data continued ...                |
// +---------------------------------------------------------------+
typedef struct wsheader_type
{
    unsigned header_size;
    bool fin;
    bool mask;
    enum opcode_type
    {
        CONTINUATION = 0x0,
        TEXT_FRAME = 0x1,
        BINARY_FRAME = 0x2,
        /*%x3 - 7 are reserved for further non-control frames*/
        CLOSE = 8,
        PING = 9,
        PONG = 0xa,
    } opcode;
    int N0;
    uint64_t N;
    uint8_t masking_key[4];
}wmm_headers;

}

#endif
