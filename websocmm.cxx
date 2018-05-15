#include "websocmm.h"
#include <process.h>
#include <stdio.h>
#include <sstream>

#define DLF_MSGLEN 1024

namespace WebsocMMM{

	WebsocMM::WebsocMM():_secure(false),
	_usemask(true),
	_socketmm(INVALID_SOCKETMM){

	}

	WebsocMM::~WebsocMM(){
	}

	bool WebsocMM::Init(const std::string& uri){
		if(!websoc_types::websoc_uri_parse(uri, _urlparts)){
			return false;
		}

		if(_urlparts.scheme == "wss"){
			_secure = true;
		}

		/*init Win-WSA env*/
		INT rc = 0;
		WSADATA _wsaData;
		rc = WSAStartup(MAKEWORD(2, 2), &_wsaData);
		if (rc) {
			OnError(WSAGetLastError(), "Initial WSAStartup failed!");
			return false;
		}

		if(_secure){
			/*init openssl env*/
			SSL_load_error_strings();    
			ERR_load_ERR_strings();
			ERR_load_crypto_strings();

			SSL_library_init();    
			_sslmeth = SSLv23_client_method();
			_sslctx = SSL_CTX_new(_sslmeth);
			if (!_sslctx){
				OnError(ERR_get_error(), "Initial SSL_CTX_new failed!");
				return false;
			}

			_ssl = SSL_new(_sslctx);
			if (!_ssl){
				OnError(ERR_get_error(), "Initial SSL_new failed!");
				return false;
			}
			SSL_CTX_set_verify(_sslctx, SSL_VERIFY_NONE, nullptr);
			SSL_set_verify(_ssl, SSL_VERIFY_NONE, nullptr);//set shakehands whatever the perr verify's result
		}

		return true;
	}

	/*release source*/
	void WebsocMM::ReleaseSSL(){
		//clean ssl env
		SSL_COMP_free_compression_methods();
		ERR_remove_state(0);
		ERR_free_strings();
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
	
		if (_ssl){
			SSL_shutdown(_ssl);
			SSL_free(_ssl);
			_ssl = nullptr;
		}
		if (_sslctx){ SSL_CTX_free(_sslctx); }

		WSACleanup();
	}

	void WebsocMM::Run(){
		/*win socket variables*/
		_socketmm = -1;

		if(!connect()){
			return;
		}

		int vsize = 0;
		_rxbuf.resize(DLF_MSGLEN);

		for(;;) {
			int r = RawRead(&_rxbuf[0] + vsize, _rxbuf.size());
			vsize += r;
			if (_secure && SSL_get_error(_ssl, r) == SSL_ERROR_WANT_READ) {
				continue;
			}else if(r==0 && WSAGetLastError() == WSA_IO_PENDING){
				continue;
			}

			if (r <= 0) {
				OnError(r, "Peer connection closed!");
				break;
			}
			else{
				if (recv_parse_handle(_rxbuf, vsize)){
					vsize = 0;
					ClearBuffer();
				}
			}
		}

		if(_secure){
			ReleaseSSL();
		}

		if(_socketmm != -1){
			closesocket(_socketmm);
		}
		WSACleanup();
	}

	/*
	release inner vector buffer
	*/
	void WebsocMM::ClearBuffer(){
		std::vector<uint8_t>().swap(_rxbuf);// free memory
		_rxbuf.resize(DLF_MSGLEN);
	}

	bool WebsocMM::connect(){
		struct addrinfo hints;
		struct addrinfo *result;
		struct addrinfo *p;
		int ret;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if ((ret = getaddrinfo(_urlparts.host.c_str(), _urlparts.port.c_str(), &hints, &result)) != 0){
			OnError(WSAGetLastError(), "Getaddrinfo failed!");
			return false;
		}
		for (p = result; p != nullptr; p = p->ai_next)
		{
			_socketmm = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
			if (_socketmm == INVALID_SOCKETMM) { continue; }
			if (::connect(_socketmm, p->ai_addr, p->ai_addrlen) != SOCKET_ERROR) {
				break;
			}
			OnError(WSAGetLastError(), "WSA connect failed!");
		}
		freeaddrinfo(result);

		if (_socketmm == INVALID_SOCKETMM) {
			return false;
		}

		if(_secure){
			if (SSL_set_fd(_ssl, _socketmm) != 1){
				OnError(ERR_get_error(), "SSL_set_fd failed!");
				return false;
			}

			if(SSL_connect(_ssl) != 1){
				//OnError(SSL_get_error(_ssl, sslconnect), "SSL_connect failed!");
				return false;
			}
		}

		//---start handshake
		int send = 0;
		char errmsg[256] = { 0 };
		// Send an initial buffer
		char line[256];
		int status = 0;
		int i;
		if (_urlparts.query.empty()){
			SPRINTFMM(line, 256, "GET /%s HTTP/1.1\r\n", _urlparts.path.c_str());  send = RawSend(line, strlen(line));
		}
		else{
			SPRINTFMM(line, 256, "GET /%s?%s HTTP/1.1\r\n", _urlparts.path.c_str(), _urlparts.query.c_str());  send = RawSend(line, strlen(line));
		}
		
		SPRINTFMM(line, 256, "HTTP/1.1 101 WebSocket Protocol Handshake\r\n"); RawSend(line, strlen(line));
		SPRINTFMM(line, 256, "Upgrade: WebSocket\r\n"); RawSend(line, strlen(line));
		SPRINTFMM(line, 256, "Connection: Upgrade\r\n"); RawSend(line, strlen(line));
		SPRINTFMM(line, 256, "Sec-WebSocket-Version: 13\r\n"); RawSend(line, strlen(line));
		SPRINTFMM(line, 256, "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"); RawSend(line, strlen(line));
		if (_urlparts.port == "80") {
			SPRINTFMM(line, 256, "Host: %s\r\n", _urlparts.host.c_str()); RawSend(line, strlen(line));
		}
		else {
			SPRINTFMM(line, 256, "Host: %s:%s\r\n", _urlparts.host.c_str(), _urlparts.port.c_str()); RawSend(line, strlen(line));
		}
		SPRINTFMM(line, 256, "Pragma: no-cache\r\n"); RawSend(line, strlen(line));
		SPRINTFMM(line, 256, "Sec-WebSocket-Protocol:\r\n\r\n"); RawSend(line, strlen(line));

		memset(line, 0, 256);
		for (i = 0; i < 2 || (i < 255 && line[i - 2] != '\r' && line[i - 1] != '\n'); ++i) {
			int sslread = SSL_read(_ssl, line + i, 1);

			if (sslread <= 0) {
				//OnError(SSL_get_error(_ssl, sslconnect), "ssl_read failed!");
				return false;
			}
		}
		line[i] = 0;
		if (i == 255){
			return false;
		}

		if (sscanf(line, "HTTP/1.1 %d", &status) != 1 || status != 101) {
			return false;
		}

		while (true) {
			memset(line, 0, 256);
			for (i = 0; i < 2 || (i < 255 && line[i - 2] != '\r' && line[i - 1] != '\n'); ++i) {
				int sslread = SSL_read(_ssl, line + i, 1);
				if (sslread == 0) {
					OnError(SSL_get_error(_ssl, sslread), "ssl_read failed!");
					return false;
				}
			}
			if (line[0] == '\r' && line[1] == '\n') { break; }
		}

		return true;
	}

	bool WebsocMM::recv_parse_handle(const std::vector<uint8_t>& rxbuf, int vsize){
		// TODO: consider acquiring a lock on rxbuf...
		while (true) {
			websoc_types::wmm_headers ws;
			if (vsize < 2) { return false; /* Need at least 2 */ }

			const uint8_t * data = (uint8_t *)&_rxbuf[0]; // peek, but don't consume
			ws.fin = (data[0] & 0x80) == 0x80;
			ws.opcode = (websoc_types::wmm_headers::opcode_type) (data[0] & 0x0f);
			ws.mask = (data[1] & 0x80) == 0x80;
			ws.N0 = (data[1] & 0x7f);
			ws.header_size = 2 + (ws.N0 == 126 ? 2 : 0) + (ws.N0 == 127 ? 8 : 0) + (ws.mask ? 4 : 0);
			if (_rxbuf.size() < ws.header_size) { return false; /* Need: ws.header_size - rxbuf.size() */ }

			int i = 0;
			if (ws.N0 < 126) {
				ws.N = ws.N0;
				i = 2;
			}
			else if (ws.N0 == 126) {
				ws.N = 0;
				ws.N |= ((uint64_t)data[2]) << 8;
				ws.N |= ((uint64_t)data[3]) << 0;
				i = 4;
			}
			else if (ws.N0 == 127) {
				ws.N = 0;
				ws.N |= ((uint64_t)data[2]) << 56;
				ws.N |= ((uint64_t)data[3]) << 48;
				ws.N |= ((uint64_t)data[4]) << 40;
				ws.N |= ((uint64_t)data[5]) << 32;
				ws.N |= ((uint64_t)data[6]) << 24;
				ws.N |= ((uint64_t)data[7]) << 16;
				ws.N |= ((uint64_t)data[8]) << 8;
				ws.N |= ((uint64_t)data[9]) << 0;
				i = 10;
			}
			if (ws.mask) {
				ws.masking_key[0] = ((uint8_t)data[i + 0]) << 0;
				ws.masking_key[1] = ((uint8_t)data[i + 1]) << 0;
				ws.masking_key[2] = ((uint8_t)data[i + 2]) << 0;
				ws.masking_key[3] = ((uint8_t)data[i + 3]) << 0;
			}
			else {
				ws.masking_key[0] = 0;
				ws.masking_key[1] = 0;
				ws.masking_key[2] = 0;
				ws.masking_key[3] = 0;
			}

			if (_rxbuf.size() < ws.header_size + ws.N) {
				_rxbuf.resize((int)(ws.header_size + ws.N));
				return false;
				/* Need: ws.header_size+ws.N - rxbuf.size() */
			}

			if(vsize < ws.header_size + ws.N){
				return false;
			}

			// We got a whole message, now do something with it:
			if (ws.opcode == websoc_types::wmm_headers::TEXT_FRAME
				|| ws.opcode == websoc_types::wmm_headers::BINARY_FRAME
				|| ws.opcode == websoc_types::wmm_headers::CONTINUATION
				) {
				if (ws.mask) {
					 for (size_t i = 0; i != ws.N; ++i) { 
						 _rxbuf[i + ws.header_size] ^= ws.masking_key[i & 0x3]; 
						} 
				}

				if (ws.fin) {
					OnMessage(_rxbuf);
				}
				else{
					OnError(3, "Receive unexpected FIN.Close socket.");
					Close();
				}
			}
			else if (ws.opcode == websoc_types::wmm_headers::PING) {

			}
			else if (ws.opcode == websoc_types::wmm_headers::PONG) {

			}
			else if (ws.opcode == websoc_types::wmm_headers::CLOSE) {
				OnClose();
			}
			else {
				OnError(3, "ERROR: Got unexpected WebSocket message.Close socket.");
				Close();
			}

			if (ws.header_size + (size_t)ws.N <= _rxbuf.size() && _rxbuf.begin() != _rxbuf.end()){
				_rxbuf.erase(_rxbuf.begin(), _rxbuf.begin() + ws.header_size + (size_t)ws.N);
			}
			std::vector<uint8_t>().swap(_rxbuf);// free memory
			break;
		}

		return true;
	}

	void WebsocMM::Close(){
		// if (_readyState == CLOSING || _readyState == CLOSED) { return; }
		// _readyState = CLOSING;
		// uint8_t closeFrame[6] = { 0x88, 0x80, 0x00, 0x00, 0x00, 0x00 }; // last 4 bytes are a masking key
		// std::vector<uint8_t> header(closeFrame, closeFrame + 6);
		// _txbuf.insert(_txbuf.end(), header.begin(), header.end());
		// int ret = 0;
		// while (_txbuf.size()) {
		// 	ret = ::SSL_write(_ssl, (char*)&_txbuf[0], _txbuf.size());
		// 	if (ret > 0) {
		// 		break;
		// 	}
		// 	else if (ret <= 0) {
		// 		_readyState = CLOSED;
		// 		//LOG(ERROR) << "Connection error! Connection closed!";
		// 	}

		// }
		// if (_txbuf.begin() != _txbuf.end() && ret <= (int)_txbuf.size()){
		// 	_txbuf.erase(_txbuf.begin(), _txbuf.begin() + ret);
		// }
		// std::vector<uint8_t>().swap(_txbuf);// free memory
		// _readyState = CLOSED;

	}

	// bool WebsocMM::sendData(wsheader_type::opcode_type type, uint64_t message_size, std::string::iterator message_begin, std::string::iterator message_end){

	// 	const uint8_t masking_key[4] = { 0x12, 0x34, 0x56, 0x78 };

	// 	if (_readyState == readyStateValues::CLOSING || _readyState == readyStateValues::CLOSED) { return false; }
	// 	std::vector<uint8_t> header;
	// 	header.assign(2 + (message_size >= 126 ? 2 : 0) + (message_size >= 65536 ? 6 : 0) + (_usemask ? 4 : 0), 0);
	// 	header[0] = 0x80 | type;
	// 	if (message_size < 126) {
	// 		header[1] = (message_size & 0xff) | (_usemask ? 0x80 : 0);
	// 		if (_usemask) {
	// 			header[2] = masking_key[0];
	// 			header[3] = masking_key[1];
	// 			header[4] = masking_key[2];
	// 			header[5] = masking_key[3];
	// 		}
	// 	}
	// 	else if (message_size < 65536) {
	// 		header[1] = 126 | (_usemask ? 0x80 : 0);
	// 		header[2] = (message_size >> 8) & 0xff;
	// 		header[3] = (message_size >> 0) & 0xff;
	// 		if (_usemask) {
	// 			header[4] = masking_key[0];
	// 			header[5] = masking_key[1];
	// 			header[6] = masking_key[2];
	// 			header[7] = masking_key[3];
	// 		}
	// 	}
	// 	else { // TODO: run coverage testing here
	// 		header[1] = 127 | (_usemask ? 0x80 : 0);
	// 		header[2] = (message_size >> 56) & 0xff;
	// 		header[3] = (message_size >> 48) & 0xff;
	// 		header[4] = (message_size >> 40) & 0xff;
	// 		header[5] = (message_size >> 32) & 0xff;
	// 		header[6] = (message_size >> 24) & 0xff;
	// 		header[7] = (message_size >> 16) & 0xff;
	// 		header[8] = (message_size >> 8) & 0xff;
	// 		header[9] = (message_size >> 0) & 0xff;
	// 		if (_usemask) {
	// 			header[10] = masking_key[0];
	// 			header[11] = masking_key[1];
	// 			header[12] = masking_key[2];
	// 			header[13] = masking_key[3];
	// 		}
	// 	}
	// 	// N.B. - txbuf will keep growing until it can be transmitted over the socket:
	// 	_txbuf.insert(_txbuf.end(), header.begin(), header.end());
	// 	_txbuf.insert(_txbuf.end(), message_begin, message_end);
	// 	if (_usemask) {
	// 		for (size_t i = 0; i != (size_t)message_size; ++i) { *(_txbuf.end() - message_size + i) ^= masking_key[i & 0x3]; }
	// 	}
	// 	while (_txbuf.size()) {
	// 		int ret = ::SSL_write(_ssl, (char*)&_txbuf[0], _txbuf.size());
	// 		if (ret > 0 && (ret == SSL_ERROR_WANT_WRITE)) {
	// 			continue;
	// 		}
	// 		else if (ret <= 0) {
	// 			_readyState = CLOSED;
	// 			fputs(ret < 0 ? "Connection error!\n" : "Connection closed!\n", stderr);
	// 			return false;
	// 		}
	// 		else {
	// 			_txbuf.erase(_txbuf.begin(), _txbuf.begin() + ret);
	// 		}
	// 	}
	// 	if (!_txbuf.size() && _readyState == CLOSING) {
	// 		_readyState = CLOSED;
	// 	}
	// 	return true;
	// }


	int WebsocMM::RawSend(const void* buffer, int num, int winflag){
		int nSend = 0;
		if(_secure){
			nSend = ::SSL_write(_ssl, buffer, num);
		}else{
			nSend = send(_socketmm, (const char*)buffer, num, winflag);
		}

		return nSend;
	}

	int WebsocMM::RawRead(void* buffer, int num,int winflag){
		int nSend = 0;
		if(_secure){
			nSend = ::SSL_read(_ssl, buffer, num);
		}else{
			nSend = recv(_socketmm, (char*)buffer, num, winflag);
		}

		return nSend;
	}
}