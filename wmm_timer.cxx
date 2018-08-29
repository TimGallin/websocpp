#include "wmm_timer.h"

namespace WebsocMMM{
	WmmTikTok::WmmTikTok(WebsocMM* wmm) :_wmm(wmm), _timeout(0), _loopctrl(1), _is_timeout(0)
	{
	}

	WmmTikTok::~WmmTikTok()
	{
	}

	void WmmTikTok::SetTimeout(int miliseconds){
		_timeout = miliseconds;
	}

	void WmmTikTok::Start(){
		_is_timeout = 1;

		if (_wmm && _timeout > 0){
			while (_loopctrl)
			{
				_wmm->SendData(websoc_types::wsheader_type::PING, NULL, 0);
				_loopctrl = 0;

				Sleep(_timeout);
			}

			//只有是超时退出情况下在外部停止websocket.由外部发起的Stop直接退出即可
			if (_is_timeout){
				_wmm->WmmExit();
			}
		}
	}

	void WmmTikTok::Stop(){
		_loopctrl = 0;
		_is_timeout = 0;
	}

	void WmmTikTok::OnStatus(Status status){
		if (status == TikTok::PONG){
			_wmm->SendData(websoc_types::wsheader_type::PONG, NULL, 0);
			_loopctrl = 1;
		}
	}
}