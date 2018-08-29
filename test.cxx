#include "wmm_timer.h"

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


#include <iostream>
#define asm_cast(var, addr)	\
{\
    	__asm					\
    	{						\
    		mov var, offset addr\
    	}						\	}

int main(int argc, char* argv[]){
	//TestWMM* ii = &tg;
	//void* p = NULL;
	//__asm					
	//{						
	//	mov p, offset WebsocMMM::WebsocMM::OnClose
	//}

	TestWMM tg;

	WebsocMMM::WmmTikTok wmmtk(&tg);
	wmmtk.SetTimeout(30000);//30s

	tg.TimerDelegate(&wmmtk);

	if (!tg.Init("wss://172.18.1.113:9108//bill-websocket/InvoiceWebSocket?name=user2") /*tg.Init("ws://172.20.113.52:8080/bill-websocket/InvoiceWebSocket?name=user2");*/){
		return 0;
	}

	while (1){
		tg.Run();
	}
	 
    return 0;
}