#include "websocmm.h"
#include <stdio.h>
#include <sstream>
#include <memory>

#define DLF_MSGLEN 2048

#define STRCMP_4(x,y1,y2,y3,y4)  \
    (x[0]==y1 && x[1]==y2 && x[2]==y3 && x[3]==y4)

#define RECV_PARSE_ERROR -1
#define RECV_PARSE_DONE 0
#define RECV_PARSE_CONTINUE 1
#define RECV_PARSE_CLOSE 2


namespace WebsocMMM{
	//----------------------------------------------

	WebsocMM::WebsocMM() :_secure(false),
		_usemask(true),
		_socketmm(INVALID_SOCKETMM),
		_rxbuf(NULL),
		_rxbuf_length(0),
		_recv_data(NULL),
		_recv_data_length(0){

	}

	bool WebsocMM::WmmInit(const std::string& uri){
		if (!websoc_types::websoc_uri_parse(uri, _urlparts)){
			return false;
		}

		if (_urlparts.scheme == "wss"){
			_secure = true;
		}

		InitWssHeaders();

		return InitSocket();
	}

	void WebsocMM::InitWssHeaders(){
		char line[512];
		memset(line, 0, 512);

		if (_urlparts.query.empty()){
			SSPRINTF(line, 256, "GET %s HTTP/1.1\r\n", _urlparts.path.c_str());
		}
		else{
			SSPRINTF(line, 256, "GET %s?%s HTTP/1.1\r\n", _urlparts.path.c_str(), _urlparts.query.c_str());
		}

		_wss_headers.emplace_back(line);
		memset(line, 0, 512);

		//
		_wss_headers.emplace_back("HTTP/1.1 101 WebSocket Protocol Handshake\r\n");
		_wss_headers.emplace_back("Upgrade:WebSocket\r\n");
		_wss_headers.emplace_back("Connection:Upgrade\r\n");
		_wss_headers.emplace_back("Pragma:no-cache\r\n");

		_wss_headers.emplace_back("Sec-WebSocket-Version: 13\r\n");
		_wss_headers.emplace_back("Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n");

		//
		if (_urlparts.port == "80") {
			SSPRINTF(line, 256, "Host: %s\r\n", _urlparts.host.c_str());
		}
		else {
			SSPRINTF(line, 256, "Host: %s:%s\r\n", _urlparts.host.c_str(), _urlparts.port.c_str());
		}

		_wss_headers.emplace_back(line);
		memset(line, 0, 512);

		//
		_wss_headers.emplace_back("Sec-WebSocket-Protocol:\r\n\r\n");

	}

	bool WebsocMM::InitSocket(){
		INT rc = 0;
		WSADATA _wsaData;
		rc = WSAStartup(MAKEWORD(2, 2), &_wsaData);
		if (rc) {
			OnError(SOCKETMM_LASTERROR, "Initial WSAStartup failed!");
			return false;
		}

#ifdef WSS_SSL
		if (_secure && !InitSSL()){
			return false;
		}
#endif

		return true;
	}

#ifdef WSS_SSL
	bool WebsocMM::InitSSL(){
		//初始化OpenSSL
		SSL_load_error_strings();
		ERR_load_ERR_strings();
		ERR_load_crypto_strings();

		SSL_library_init();
		const SSL_METHOD* sslmeth = SSLv23_client_method();
		_sslctx = SSL_CTX_new(sslmeth);
		if (!_sslctx){
			OnError(ERR_get_error(), "Initial SSL_CTX_new failed!");
			return false;
		}

		_ssl = SSL_new(_sslctx);
		if (!_ssl){
			OnError(ERR_get_error(), "Initial SSL_new failed!");
			return false;
		}

		//默认不使用SSL验证
		SSL_CTX_set_verify(_sslctx, SSL_VERIFY_NONE, nullptr);
		SSL_set_verify(_ssl, SSL_VERIFY_NONE, nullptr);//set shakehands whatever the perr verify's result

		return true;
	}

	void WebsocMM::ReleaseSSL(){
		//释放SSL环境
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
		if (_sslctx){
			SSL_CTX_free(_sslctx);
			_sslctx = nullptr;
		}
	}
#endif

	bool WebsocMM::Connect(){
		struct addrinfo hints;
		struct addrinfo *result;
		struct addrinfo *p;
		int ret;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if ((ret = getaddrinfo(_urlparts.host.c_str(), _urlparts.port.c_str(), &hints, &result)) != 0){
			OnError(SOCKETMM_LASTERROR, "Getaddrinfo failed!");
			return false;
		}

		for (p = result; p != nullptr; p = p->ai_next)
		{
			_socketmm = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
			if (_socketmm == INVALID_SOCKETMM) {
				continue;
			}

			if (::connect(_socketmm, p->ai_addr, p->ai_addrlen) != SOCKETMM_ERROR) {
				break;
			}
			OnError(SOCKETMM_LASTERROR, "WSA connect failed!");

			SOCKETMM_CLOSE(_socketmm);
			_socketmm = INVALID_SOCKET;
		}
		freeaddrinfo(result);

		if (_socketmm == INVALID_SOCKETMM) {
			return false;
		}

#ifdef WSS_SSL
		if (_secure){

			if (SSL_set_fd(_ssl, _socketmm) != 1){
				OnError(ERR_get_error(), "SSL_set_fd failed!");
				return false;
			}

			if (SSL_connect(_ssl) != 1){
				//OnError(SSL_get_error(_ssl, sslconnect), "SSL_connect failed!");
				return false;
			}
		}
#endif

		return true;
	}

	bool WebsocMM::ShakeHands(){
		//发送握手请求
		int s = 0;
		for (const std::string& header : _wss_headers){
#ifdef WSS_SSL
			s = ::SSL_write(_ssl, header.c_str(), header.length());
#else
			s = send(_socketmm, header.c_str(), header.length(), 0);
#endif
		}

		//等待服务器响应并读取返回
		std::unique_ptr<char[]> rxbuf(new char[DLF_MSGLEN]());
		int r = 0, length = 0;

		while (1){
#ifdef WSS_SSL
			r = ::SSL_read(_ssl, rxbuf.get() + length, DLF_MSGLEN);
#else
			r = recv(_socketmm, rxbuf.get() + length, DLF_MSGLEN, 0);
#endif

			if (r <= 0) {
				return false;
			}

			length += r;

			if (length < 5){
				continue;
			}

			if (STRCMP_4((rxbuf.get() + length - 4), '\r', '\n', '\r', '\n')){
				break;
			}

			if (length == DLF_MSGLEN){
				std::unique_ptr<char[]> newbuf(new char[2 * length]());
				memcpy(newbuf.get(), rxbuf.get(), length);
				rxbuf.swap(newbuf);
				continue;
			}
		}

		int status = 0;
		
		std::vector<std::string> _wss_respond_headers;
		if (!websoc_types::parse_headers_respond(rxbuf.get(), length, status, _wss_respond_headers)){
			return false;
		}

		if (status != 200 && status != 101){
			return false;
		}

		OnSetup(_wss_respond_headers);

		return true;
	}

	void WebsocMM::WmmRun(){
		if (!Connect()){
			return;
		}

		if (!ShakeHands()){
			return;
		}

		//当前_rxbuf有效的长度
		unsigned int valid_size = 0;

		_rxbuf = new unsigned char[DLF_MSGLEN]();
		_rxbuf_length = DLF_MSGLEN;

		for (;;) {
#ifdef WSS_SSL
			int r = 0;
			if (_secure){
				r = ::SSL_read(_ssl, (char*)_rxbuf + valid_size, _rxbuf_length - valid_size);

				if (_secure && SSL_get_error(_ssl, r) == SSL_ERROR_WANT_READ) {
					continue;
				}
			}
			else
			{
				r = recv(_socketmm, (char*)_rxbuf + valid_size, _rxbuf_length - valid_size, 0);
				if (r == 0 && SOCKETMM_LASTERROR == SOCKET_IOPENDING){
					continue;
				}
			}
#else
			int r = recv(_socketmm, (char*)_rxbuf + valid_size, _rxbuf_length - valid_size, 0);
			if (r == 0 && SOCKETMM_LASTERROR == SOCKET_IOPENDING){
				continue;
			}
#endif

			if (r <= 0) {
				OnError(SOCKETMM_LASTERROR, "Peer connection closed!");
				break;
			}

			valid_size += r;

			int parse = RecvHandle(_rxbuf, valid_size);
			if (parse == RECV_PARSE_DONE){
				delete[] _rxbuf;
				valid_size = 0;

				_rxbuf = new unsigned char[DLF_MSGLEN]();
				_rxbuf_length = DLF_MSGLEN;
			}
			else if (parse == RECV_PARSE_CLOSE || parse == RECV_PARSE_ERROR){

				break;
			}
		}

		if (_rxbuf){
			delete[] _rxbuf;
			_rxbuf_length = 0;
		}

		if (_socketmm != INVALID_SOCKETMM){
			SOCKETMM_CLOSE(_socketmm);
		}
	}

	int WebsocMM::RecvHandle(unsigned char* rxbuf, unsigned int& valid_size){
		// TODO: consider acquiring a lock on rxbuf...
		while (true) {
			websoc_types::wmm_headers ws;
			if (valid_size < 2) { return false; /* Need at least 2 */ }

			const uint8_t * data = (uint8_t *)_rxbuf; // peek, but don't consume
			ws.fin = (data[0] & 0x80) == 0x80;
			ws.opcode = (websoc_types::wmm_headers::opcode_type) (data[0] & 0x0f);
			ws.mask = (data[1] & 0x80) == 0x80;
			ws.N0 = (data[1] & 0x7f);
			ws.header_size = 2 + (ws.N0 == 126 ? 2 : 0) + (ws.N0 == 127 ? 8 : 0) + (ws.mask ? 4 : 0);
			if (valid_size < ws.header_size) {
				return RECV_PARSE_CONTINUE; /* Need: ws.header_size - rxbuf.size() */
			}

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

			if (_rxbuf_length < ws.header_size + ws.N) {
				//重新分配空间，将原有空间内有效的内容拷贝至新空间。 由于掩码的原因，这里不宜直接将Header舍弃
				_rxbuf_length = ws.header_size + (unsigned int)ws.N;
				unsigned char* tpbuf = new unsigned char[_rxbuf_length]();

				memcpy(tpbuf, _rxbuf, valid_size);
				delete[] _rxbuf;

				_rxbuf = tpbuf;
				tpbuf = NULL;

				return RECV_PARSE_CONTINUE;
				/* Need: ws.header_size+ws.N - rxbuf.size() */
			}

			if (valid_size < ws.header_size + ws.N){
				return RECV_PARSE_CONTINUE;
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

				//重新分配recv_data buffer
				unsigned char* tpbuf = new unsigned char[_recv_data_length + (unsigned int)ws.N]();

				if (_recv_data_length > 0){
					//将原有内容复制到新的recv缓冲区，释放原缓冲区，将recv_data指向新的buffer
					memcpy(tpbuf, _recv_data, _recv_data_length);
					delete[] _recv_data;
				}

				_recv_data = tpbuf;

				//将掩码处理后的内容主体追加到recv_data,更新_recv_data_length长度
				memcpy(_recv_data + _recv_data_length, _rxbuf + ws.header_size, (unsigned int)ws.N);
				_recv_data_length += (unsigned int)ws.N;

				//重置_rxbuf
				memset(_rxbuf, 0, _rxbuf_length);
				valid_size = 0;

				if (ws.fin) {
					OnMessage(ws.opcode, (char*)(_recv_data), _recv_data_length);
				}
				else{
					return RECV_PARSE_CONTINUE;
				}
			}
			else if (ws.opcode == websoc_types::wmm_headers::PING) {
				OnMessage(ws.opcode, NULL, 0);
			}
			else if (ws.opcode == websoc_types::wmm_headers::PONG) {
				OnMessage(ws.opcode, NULL, 0);
			}
			else if (ws.opcode == websoc_types::wmm_headers::CLOSE) {
				OnClose();

				return RECV_PARSE_CLOSE;
			}
			else {
				OnError(3, "ERROR: Got unexpected WebSocket message.Close socket.");
				return RECV_PARSE_ERROR;
			}

			break;
		}

		//清理recv_data buffer
		if (_recv_data){
			delete[] _recv_data;
			_recv_data_length = 0;
		}

		return RECV_PARSE_DONE;
	}

	void WebsocMM::WmmClose(){
		uint8_t closeFrame[6] = { 0x88, 0x80, 0x00, 0x00, 0x00, 0x00 }; // last 4 bytes are a masking key

		SendData(websoc_types::wmm_headers::CLOSE, (char*)closeFrame, 6 * sizeof(uint8_t));
	}

	void WebsocMM::WmmExit(){
		if (_socketmm != INVALID_SOCKETMM){
			SOCKETMM_CLOSE(_socketmm);
			_socketmm = INVALID_SOCKETMM;
		}
	}

	void WebsocMM::WmmUnInit(){
#ifdef WSS_SSL
		if (_secure){
			ReleaseSSL();
		}
#endif

		if (_socketmm != INVALID_SOCKETMM){
			SOCKETMM_CLOSE(_socketmm);
		}

		WSACleanup();
	}

	bool WebsocMM::SendData(websoc_types::wmm_headers::opcode_type type, const char* message_begin, uint64_t message_size){
		std::unique_lock<std::mutex> lock(_send_mutex);

		if (_socketmm == INVALID_SOCKETMM){
			return false;
		}

		const uint8_t masking_key[4] = { 0x12, 0x34, 0x56, 0x78 };

		std::vector<uint8_t> header;
		header.assign(2 + (message_size >= 126 ? 2 : 0) + (message_size >= 65536 ? 6 : 0) + (_usemask ? 4 : 0), 0);
		header[0] = 0x80 | type;
		if (message_size < 126) {
			header[1] = (message_size & 0xff) | (_usemask ? 0x80 : 0);
			if (_usemask) {
				header[2] = masking_key[0];
				header[3] = masking_key[1];
				header[4] = masking_key[2];
				header[5] = masking_key[3];
			}
		}
		else if (message_size < 65536) {
			header[1] = 126 | (_usemask ? 0x80 : 0);
			header[2] = (message_size >> 8) & 0xff;
			header[3] = (message_size >> 0) & 0xff;
			if (_usemask) {
				header[4] = masking_key[0];
				header[5] = masking_key[1];
				header[6] = masking_key[2];
				header[7] = masking_key[3];
			}
		}
		else { // TODO: run coverage testing here
			header[1] = 127 | (_usemask ? 0x80 : 0);
			header[2] = (message_size >> 56) & 0xff;
			header[3] = (message_size >> 48) & 0xff;
			header[4] = (message_size >> 40) & 0xff;
			header[5] = (message_size >> 32) & 0xff;
			header[6] = (message_size >> 24) & 0xff;
			header[7] = (message_size >> 16) & 0xff;
			header[8] = (message_size >> 8) & 0xff;
			header[9] = (message_size >> 0) & 0xff;
			if (_usemask) {
				header[10] = masking_key[0];
				header[11] = masking_key[1];
				header[12] = masking_key[2];
				header[13] = masking_key[3];
			}
		}

		std::unique_ptr<char[]> datasend(new char[header.size() + (uint32_t)message_size]());
		memcpy(datasend.get(), &header[0], header.size());


		if (_usemask && message_begin != NULL) {
			int offset = header.size();
			memcpy(datasend.get() + offset, message_begin, (size_t)message_size);

			for (size_t i = 0; i != (size_t)message_size; ++i) { *(datasend.get() + offset + i) ^= masking_key[i & 0x3]; }
		}

		message_size += header.size();
		while (message_size) {
#ifdef WSS_SSL
			int r = ::SSL_write(_ssl, datasend.get(), (int)message_size);
			if (r > 0 && (r == SSL_ERROR_WANT_WRITE)) {
				continue;
			}
			else if (r <= 0) {
				OnError(SSL_get_error(_ssl, r), "Write error.");
				return false;
			}
#else
			int r = ::send(_socketmm, datasend.get(), (int)header.size() + message_size, 0);
			if (r <= 0) {
				OnError(SOCKETMM_LASTERROR, "Write error.");
				return false;
			}
#endif
			else {
				message_size -= r;
			}
		};

		return message_size == 0;

	}

}
