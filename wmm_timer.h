#include "websocmm.h"

namespace WebsocMMM{
	//------------My TikTok Timer--------------------------
	class WmmTikTok : public TikTok
	{
	public:
		WmmTikTok(WebsocMM* wmm);
		~WmmTikTok();

		void SetTimeout(int miliseconds);

		void Start() override;

		void Stop() override;

		void OnStatus(Status status) override;
	private:
		int _timeout;

		WebsocMM* _wmm;

		int _loopctrl;

		int _is_timeout;
	};
}