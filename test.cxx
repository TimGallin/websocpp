#include "websocmm.h"

class TestWMM : public WebsocMMM::WebsocMM
{
public:
	TestWMM(){};
	~TestWMM(){};

	virtual void OnMessage(std::vector<uint8_t>& sMessage) override{
		int mm = 0;
	}

	virtual void OnClose() override{

	}

	virtual void OnError(int code, const std::string& message) override{
		
	}

};



int main(int argc, char* argv[]){

	TestWMM tg;
    tg.Init("wss://172.18.1.113:9108/bill-websocket/WebSocket?name=150301206811299421000");
    tg.Run();
    
    return 0;
}