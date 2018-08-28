#include "wmm_types.h"

#define STRCMP_2(x,y1,y2)  \
    (x[0]==y1 && x[1]==y2)

#define STRCMP_3(x,y1,y2,y3)  \
    (x[0]==y1 && x[1]==y2 && x[2]==y3)

namespace websoc_types
{
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
					if (STRCMP_3(ite, ':', '/', '/')){
						state = sw_host;
						ite += 2;
						break;
					}
                        
                    parts.scheme.append(1,ch);
                    break;
                
                case sw_host:
                    if(ch == ':'){
                        state = sw_port;
                        break;
                    }
                    else if(ch == '?'){
                        state = sw_query;
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

	bool parse_headers_respond(char* respond, int length, int& status, std::vector<std::string>& headers){
		if (respond == nullptr){
			return false;
		}

		status = 0;
		char* pos = respond;
		for (int i = 0; i < length; ++i){
			if (STRCMP_2((respond + i), '\r', '\n')){
				*(respond + i) = 0;

				if (status == 0 && memcmp(pos, "HTTP", 4) == 0){
						char* space = NULL;
						space = strchr(pos, ' ');

						if (space != NULL){
							status = atoi(space + 1);
						}
				}

				headers.emplace_back(pos);
				pos = respond + i + 1;
			}
		}

		return true;
	}
}