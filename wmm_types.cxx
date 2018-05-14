#include "wmm_types.h"


#define STRCMP_3(x,y1,y2,y3)  \
    (x[0]==y1 && x[1]==y2 && x[2]==y3)

namespace websoc_types
{
    /*URI = "ws:" "//" host [ ":" port ] path [ "?" query ]*/
    bool websoc_uri_parse(const std::string &uri, urlparts &parts){
        enum {
            sw_scheme = 0,
            sw_host,
            sw_colon,
            sw_port,
            sw_path,
            sw_query
        }state = sw_scheme;

        std::string::const_iterator ite = uri.cbegin();

        for(ite; ite != uri.cend(); ++ite){
            char ch = *ite;

            switch(state){
                case sw_scheme:
                    if(STRCMP_3((char*)&ch, ':', '/','/') == 0)
                        state = sw_host;
                        ite += 2;
                        break;
                    
                    parts.scheme.append(1,ch);
                    break;
                
                case sw_host:
                    if(ch == ':'){
                        state = sw_port;
                        ++ite;
                        break;
                    }
                    else if(ch == '?'){
                        state = sw_query;
                        ++ite;
                        break;
                    }
                    else if(ch == '/'){
                        state = sw_path;
                        parts.path.append(1,ch);
                        break;
                    }

                    parts.host.append(1,ch);
                    break;

                case sw_port:
                    if(ch == '?'){
                        state = sw_query;
                        ++ite;
                        break;
                    }
                    else if(ch == '/'){
                        state = sw_path;
                        parts.path.append(1,ch);
                        break;
                    }

                    parts.port.append(1,ch);
                    break;

                case sw_path:
                    if(ch == '?'){
                        state = sw_query;
                        ++ite;
                        break;
                    }

                    parts.path.append(1,ch);
                    break;

                case sw_query:
                    parts.query.append(1,ch);
                    break;

                default :
                    break;
            }

        }
        
        if(parts.port.empty()){
            parts.port = parts.scheme == "wss" ? "443" : "80";
        }

        return true;
    }
}