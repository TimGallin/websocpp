#include "websocmm.h"
#include <thread>
class TestWMM : public WebsocMMM::WebsocMM
{
public:
	TestWMM() :_loopctrl(NULL){

	//	_hNotify = CreateEvent(NULL, TRUE, TRUE, L"5C6C8ECE-1002-46E5-B19D-95308563B2B4");
	};
	~TestWMM(){
	//	if (_hNotify){
	//		*_loopctrl = 0;
	//		SetEvent(_hNotify);
	//		CloseHandle(_hNotify);
		}
	};

	virtual void OnMessage(websoc_types::wmm_headers::opcode_type type, char* message, int length) override{
		if (type == websoc_types::wmm_headers::opcode_type::PONG){
	//		if (_hNotify){
	//			SetEvent(_hNotify);
	//		}
		}
		else
		{

		}
		int mm = 0;
	};

	virtual void OnClose() override{
		int mm = 0;
	};

	virtual void OnError(int code, const std::string& message) override{
		int mm = 0;
	};

	virtual void OnSetup(std::vector<std::string>& wssheaders) override{
	//	_loopctrl = new int(1);

		//如果有定时器的话先开启定时器
	//	std::thread td([this](){
	//		HANDLE hNotify = OpenEvent(EVENT_ALL_ACCESS, NULL, L"5C6C8ECE-1002-46E5-B19D-95308563B2B4");
	//		if (hNotify == NULL || _loopctrl == NULL){
	//			return;
	//		}

	//		DWORD wait = 0;
	//		while (*_loopctrl){
	//			SendData(websoc_types::wsheader_type::PING, NULL, 0);

	//			Sleep(5000);
	//			wait = WaitForSingleObject(hNotify, 0);

				//只有是超时退出情况下在外部停止websocket.由外部发起的Stop直接退出即可
	//			if (wait == WAIT_TIMEOUT){
	//				WmmExit();

	//				break;
	//			}
	//		}

	//		if (hNotify){
	//			CloseHandle(hNotify);
	//		}

	//		delete _loopctrl;
	//	});

	//	td.detach();
	};

private:
	//HANDLE _hNotify;
	int* _loopctrl;
};


int main(int argc, char* argv[]){
	TestWMM tg;

	if (!tg.WmmInit("wss://172.18.1.113:9108//bill-websocket/InvoiceWebSocket?name=user2") /*tg.Init("ws://172.20.113.52:8080/bill-websocket/InvoiceWebSocket?name=user2");*/){
		return 0;
	}

	while (1){
		tg.WmmRun();
		sleep(10000);
		break;
	}

	tg.WmmUnInit();
	return 0;
}
