#pragma once
// refer to
// https://github.com/dhbaird/easywsclient
//

#include <string>
#include <vector>
#include <stdint.h>

#include "wmm_types.h"

#include <openssl\ssl.h>
#include <openssl\err.h>
#include <openssl\bio.h>
#pragma warning(disable:4290)
#pragma warning(disable:4482)



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
		close this websocket.send close frame and then close sslsocket.
		*/
		void Close();

		/*
		init wsa and openssl env.
		*/
		bool Init(const std::string& uri);


		virtual void OnMessage(std::vector<uint8_t>& sMessage) = 0;

		virtual void OnClose() = 0;

		virtual void OnError(int code, const std::string& message) = 0;

	private:
		bool connect();

		/*
		parse respondse.
		@param rxbuf : received data buffer
		@param p : size of valid data in buffer 
		*/
		bool recv_parse_handle(const std::vector<uint8_t>& rxbuf, int vsize);

		/*
		send data,
		*/
		//bool sendData(websoc_types::wmm_headers::opcode_type type, uint64_t message_size, std::string::iterator message_begin, std::string::iterator message_end);

		/*
		release inner vector buffer
		*/
		void ClearBuffer();

		/*
		release SSL 
		*/
		void ReleaseSSL();


		int RawSend(const void* buffer, int num, int winflag = 0);

		int RawRead(void* buffer, int num, int winflag = 0);

		//variables
		websoc_types::urlparts _urlparts;

		std::vector<uint8_t> _rxbuf;//read buf
		std::vector<uint8_t> _txbuf;//write buf

		bool _usemask;

		bool _secure;

		struct addrinfo *addrResult, *ptr, hints;

		//Win
		int _socketmm;
		/*openssl variables*/
		SSL_CTX* _sslctx;
		SSL* _ssl;

	};
}
