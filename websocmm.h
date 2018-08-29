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
		����Close��Ϣ��������
		�����������������½���ظ�Close��Ϣ��Client�ڽ��յ�Close�󽫻��˳�
		*/
		void WmmClose();

		/*
		�ر�Socket
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
		����URI��ʼ������ͷ��
		*/
		void InitWssHeaders();

		/*
		���ӷ�����
		*/
		bool Connect();

		/*
		����Ŀ�����������������
		*/
		bool ShakeHands();

		/*
		��ʼ������⻷��
		*/
		bool InitSocket();

#ifdef WSS_SSL
		/*
		��ʼ��SSL����
		*/
		bool InitSSL();

		/*
		�ͷ�SSL����
		*/
		void ReleaseSSL();
#endif

		/*
		�ͷ�����⻷��
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

		//�Ƿ��� WSS
		bool _secure;

		//websocket ����ͷ��
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
