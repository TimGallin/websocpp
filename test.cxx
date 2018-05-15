#include "websocmm.h"

int main(int argc, char* argv[]){

    WebsocMMM::WebsocMM tg;
    tg.Init("wss://172.18.1.113:9108/bill-websocket/WebSocket?name=150301206811299421000");
    tg.Run();
    
    return 0;
}