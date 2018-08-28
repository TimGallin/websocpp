#pragma once
// refer to
// https://github.com/dhbaird/easywsclient
//

#include <string>
#include <vector>
#include <stdint.h>

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

	class WebsocMM
	{
	public:
		WebsocMM();
		virtual ~WebsocMM();

		/*
		Run
		*/
		void Run();

		/*
		发送Close消息到服务器
		服务器在正常流程下将会回复Close消息，Client在接收到Close后将会退出
		*/
		void Close();

		/*
		关闭Socket
		*/
		void Exit();

		/*
		init wsa and openssl env.
		*/
		bool Init(const std::string& uri);

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

		/*
		send data,
		*/
		//bool sendData(websoc_types::wmm_headers::opcode_type type, uint64_t message_size, std::string::iterator message_begin, std::string::iterator message_end);

		//variables
		websoc_types::urlparts _urlparts;

		//
		unsigned char* _rxbuf;
		unsigned int _rxbuf_length;

		unsigned char* _recv_data;
		unsigned int _recv_data_length;

		std::vector<uint8_t> _txbuf;//write buf

		bool _usemask;

		bool _secure;

		struct addrinfo *addrResult, *ptr, hints;

		//websocket 请求头部
		std::vector<std::string> _wss_headers;

		//Win
		int _socketmm;

#ifdef WSS_SSL
		/*openssl variables*/
		SSL_CTX* _sslctx;
		SSL* _ssl;
#endif
	};
}
