#include "websocmm.h"

class TestWMM : public WebsocMMM::WebsocMM
{
public:
	TestWMM(){};
	~TestWMM(){};

	virtual void OnMessage(char* message, int length) override{
		int mm = 0;
	}

	virtual void OnClose() override{
		int mm = 0;
	}

	virtual void OnError(int code, const std::string& message) override{
		int mm = 0;
	}

	virtual void OnSetup(std::vector<std::string>& wssheaders) override{
		int mm = 0;
	}
};



int main(int argc, char* argv[]){
	TestWMM tg;
    tg.Init("wss://172.18.1.113:9108//bill-websocket/InvoiceWebSocket?name=user2");
	//tg.Init("ws://172.20.113.52:8080/bill-websocket/InvoiceWebSocket?name=user2");
    tg.Run();
    
    return 0;
}