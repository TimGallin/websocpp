#pragma once

#include <string>
#include <vector>
#include <stdint.h>
#include <mutex>

#include "wmm_types.h"

#define WSS_SSL

#ifdef WSS_SSL
#include <openssl\ssl.h>
#include <openssl\err.h>
#include <openssl\bio.h>
#pragma warning(disable:4290)
#pragma warning(disable:4482)
#endif


namespace WebsocMMM{
	//------------V-Base TikTok----------------------------------
	class TikTok
	{
	public:
		enum Status
		{
			PING,
			PONG
		};

		//TikTok();
		virtual ~TikTok(){};

		virtual void Start() = 0;

		virtual void Stop() = 0;

		virtual void OnStatus(Status status) = 0;
	};

	//------------WebsocMM----------------------------------

	class WebsocMM
	{
	public:
		WebsocMM();
		virtual ~WebsocMM(){};

		/*
		Run
		*/
		void WmmRun();

		/*
		发送Close消息到服务器
		服务器在正常流程下将会回复Close消息，Client在接收到Close后将会退出
		*/
		void WmmClose();

		/*
		关闭Socket
		*/
		void WmmExit();

		/*
		init wsa and openssl env.
		*/
		bool WmmInit(const std::string& uri);

		/*
		Send Data
		*/
		bool SendData(websoc_types::wmm_headers::opcode_type type, const char* message_begin, uint64_t message_size);


		/*
		Set Timer
		*/
		void TimerDelegate(TikTok* delegate);

		//-----------------Interface-------------------
		virtual void OnSetup(std::vector<std::string>& wssheaders) = 0;

		virtual void OnMessage(char* message, int length) = 0;
		
		virtual void OnClose() = 0;

		virtual void OnError(int code, const std::string& message) = 0;

	private:
		/*
		根据URI初始化请求头部
		*/
		void InitWssHeaders();

		/*
		连接服务器
		*/
		bool Connect();

		/*
		连接目标服务器并进行握手
		*/
		bool ShakeHands();

		/*
		初始化网络库环境
		*/
		bool InitSocket();

#ifdef WSS_SSL
		/*
		初始化SSL环境
		*/
		bool InitSSL();

		/*
		释放SSL环境
		*/
		void ReleaseSSL();
#endif

		/*
		释放网络库环境
		*/
		void ReleaseSocket();

		/*
		parse respondse.
		@param rxbuf : received data buffer
		@param p : size of valid data in buffer 
		*/
		int RecvHandle(unsigned char* rxbuf, unsigned int& valid_size);


		//variables
		websoc_types::urlparts _urlparts;

		//recv buffer
		unsigned char* _rxbuf;
		unsigned int _rxbuf_length;

		//recv data buffer
		unsigned char* _recv_data;
		unsigned int _recv_data_length;

		std::mutex _send_mutex;

		TikTok* _tiktok_delegate;

		bool _usemask;

		//是否是 WSS
		bool _secure;

		//websocket 请求头部
		std::vector<std::string> _wss_headers;

		//Socket
		int _socketmm;

#ifdef WSS_SSL
		//SSL
		SSL_CTX* _sslctx;
		SSL* _ssl;
#endif
	};

}
