#include "websocmm.h"
#include <thread>


class TestWMM : public WebsocMMM::WebsocMM
{
public:
	TestWMM();
	~TestWMM();

	virtual void OnMessage(websoc_types::wmm_headers::opcode_type type, char* message, int length) override;

	virtual void OnClose() override;

	virtual void OnError(int code, const std::string& message) override;

	virtual void OnSetup(std::vector<std::string>& wssheaders) override;

private:
	//HANDLE _hNotify;
	int* _loopctrl;
};

