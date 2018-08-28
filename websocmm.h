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
		����Close��Ϣ��������
		�����������������½���ظ�Close��Ϣ��Client�ڽ��յ�Close�󽫻��˳�
		*/
		void Close();

		/*
		�ر�Socket
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

		//websocket ����ͷ��
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
