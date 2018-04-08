#include "websoc_client.h"
#include <process.h>
#include <stdio.h>
#include "../glog/gloghelper.h"

unsigned _stdcall thread_heartbeats(void* arg);


websoc_client::websoc_client(){

	_usemask = true;
	_contentLen = 2;//一条websoc消息长度至少为2

	_hbVal = PING;//初始化为PING 收到PONG后改为PONG


	std::vector<uint8_t>().swap(_receivedData);// free memory

	_nHbControl = 1;

	InitializeCriticalSectionAndSpinCount(&_cs, 4000);
}

int websoc_client::GetHbControl(){
	return _nHbControl;
}

bool websoc_client::InitEnv(){
	/*split full uri*/
	char hostbuf[128] = { 0 };
	char pathbuf[512] = { 0 };
	if (false) {}
	else if (sscanf_s(_sUri.c_str(), "wss://%[^:/]:%d/%s", hostbuf, 128, &_port, pathbuf, 512) == 3) {

	}
	else if (sscanf_s(_sUri.c_str(), "wss://%[^:/]/%s", hostbuf, 128, pathbuf, 512) == 2) {
		_port = 443;
	}
	else if (sscanf_s(_sUri.c_str(), "wss://%[^:/]:%d", hostbuf, 128, &_port) == 2) {
		_path = "";
	}
	else if (sscanf_s(_sUri.c_str(), "wss://%[^:/]", hostbuf, 128) == 1) {
		_port = 443;
		_path = "";
	}
	else {
		OnError(2, "Could not parse WebSocket url!");
		return false;
	}
	_path = pathbuf;
	_host = hostbuf;
	/*init wsa env*/
	INT rc = 0;
	rc = WSAStartup(MAKEWORD(2, 2), &_wsaData);
	if (rc) {
		OnError(socketerrno, "Initial WSAStartup failed!");
		return false;
	}
	/*init openssl env*/
	SSL_load_error_strings();    // 错误信息的初始化
	ERR_load_ERR_strings();
	ERR_load_crypto_strings();

	SSL_library_init();    // 初始化SSL算法库函数( 加载要用到的算法 )
	_sslmeth = SSLv23_client_method();
	_sslctx = SSL_CTX_new(_sslmeth);
	if (!_sslctx){
		OnError(ERR_get_error(), "Initial SSL_CTX_new failed!");
		return false;
	}

	SSL_CTX_set_verify(_sslctx, SSL_VERIFY_NONE, NULL);
	_ssl = SSL_new(_sslctx);
	if (!_ssl){
		OnError(ERR_get_error(), "Initial SSL_new failed!");
		return false;
	}
	SSL_set_verify(_ssl, SSL_VERIFY_NONE, NULL);//set shakehands whatever the perr verify's result
	return true;
}

websoc_client::~websoc_client(){
	DeleteCriticalSection(&_cs);
}

websoc_client::HearbeatsStateValues websoc_client::GetHbValue(){
	EnterCriticalSection(&_cs);
	HearbeatsStateValues tmp = _hbVal;
	LeaveCriticalSection(&_cs);
	return tmp;
}

/*get heartbeats state*/
void websoc_client::SetHbValue(const HearbeatsStateValues& hbVal){
	EnterCriticalSection(&_cs);
	_hbVal = hbVal;
	LeaveCriticalSection(&_cs);

}


/*release source*/
bool websoc_client::Uninit(){
	//clean ssl env
	SSL_COMP_free_compression_methods();
	ERR_remove_state(0);
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	if (_ssl){ SSL_shutdown(_ssl); }
	if (_ssl){
		SSL_free(_ssl); 
		_ssl = NULL;
	}
	if (_sslctx){ SSL_CTX_free(_sslctx); }
	//clean wsa env
	if (_websocfd != INVALID_SOCKET){ 
		closesocket(_websocfd); 
		_websocfd = INVALID_SOCKET;
	}
	WSACleanup();

	return true;
}

/*
set uri
*/
void websoc_client::SetUri(LPCSTR fullurl){
	_sUri = fullurl;
}

/*
release inner vector buffer
*/
void websoc_client::releaseVecbuf(){
	std::vector<uint8_t>().swap(_rxbuf);// free memory
	_rxbuf.resize(0);
	std::vector<uint8_t>().swap(_receivedData);// free memory
	_receivedData.resize(0);
}

bool websoc_client::connect(){
	struct addrinfo hints;
	struct addrinfo *result;
	struct addrinfo *p;
	int ret;
	_websocfd = INVALID_SOCKET;
	char sport[16];
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	sprintf_s(sport, 16, "%d", _port);
	if ((ret = getaddrinfo(_host.c_str(), sport, &hints, &result)) != 0){
		OnError(socketerrno, "Getaddrinfo failed!");
		return false;
	}
	for (p = result; p != NULL; p = p->ai_next)
	{
		_websocfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (_websocfd == INVALID_SOCKET) { continue; }
		if (::connect(_websocfd, p->ai_addr, p->ai_addrlen) != SOCKET_ERROR) {
			break;
		}
		OnError(socketerrno, "WSA connect failed!");
		closesocket(_websocfd);
		_websocfd = INVALID_SOCKET;
	}
	freeaddrinfo(result);

	if (_websocfd == INVALID_SOCKET) {
		return false;
	}

	if (SSL_set_fd(_ssl, _websocfd) != 1){
		OnError(ERR_get_error(), "SSL_set_fd failed!");
		return false;
	}

	int sslconnect = SSL_connect(_ssl);
	if (sslconnect != 1){
		OnError(SSL_get_error(_ssl, sslconnect), "SSL_connect failed!");
		return false;
	}
	//---start handshake
	int send = 0;
	char errmsg[256] = { 0 };
	// Send an initial buffer
	char line[256];
	int status = 0;
	int i;
	sprintf_s(line, 256, "GET /%s HTTP/1.1\r\n",_path.c_str());  ::SSL_write(_ssl, line, strlen(line));
	sprintf_s(line, 256, "HTTP/1.1 101 WebSocket Protocol Handshake\r\n"); send = ::SSL_write(_ssl, line, strlen(line)); 
	sprintf_s(line, 256, "Upgrade: WebSocket\r\n"); ::SSL_write(_ssl, line, strlen(line));
	sprintf_s(line, 256, "Connection: Upgrade\r\n"); ::SSL_write(_ssl, line, strlen(line));
	sprintf_s(line, 256, "Sec-WebSocket-Version: 13\r\n"); ::SSL_write(_ssl, line, strlen(line));
	sprintf_s(line, 256, "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"); ::SSL_write(_ssl, line, strlen(line));
	if (_port == 80) {
		sprintf_s(line, 256, "Host: %s\r\n", _host.c_str()); ::SSL_write(_ssl, line, strlen(line));
	}
	else {
		sprintf_s(line, 256, "Host: %s:%d\r\n", _host.c_str(), _port); ::SSL_write(_ssl, line, strlen(line));
	}
	sprintf_s(line, 256, "Pragma: no-cache\r\n"); ::SSL_write(_ssl, line, strlen(line));
	sprintf_s(line, 256, "Sec-WebSocket-Protocol:\r\n\r\n"); ::SSL_write(_ssl, line, strlen(line));

	memset(line, 0, 256);
	for (i = 0; i < 2 || (i < 255 && line[i - 2] != '\r' && line[i - 1] != '\n'); ++i) {//读取首行response
		int sslread = SSL_read(_ssl, line + i, 1);
		/**/
		printf(line + i);
		if (sslread <= 0) {
			OnError(SSL_get_error(_ssl, sslconnect), "ssl_read failed!");
			return false;
		}
	}
	line[i] = 0;
	if (i == 255){//读取错误
		OnError(SSL_get_error(_ssl, -1), line);
		return false;
	}
	if (sscanf_s(line, "HTTP/1.1 %d", &status) != 1 || status != 101) {//status ！= 101 或者sscanf失败 websoc握手失败
		OnError(SSL_get_error(_ssl, -1), line);
		return false;
	}
	while (true) {//读取所有websoc握手返回信息，清空socket读缓冲区
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
	_readyState = readyStateValues::OPEN;


	/*
	start heartbeats thread
	*/
	_nHbControl = 1;
	HANDLE hHeartBeats = (HANDLE)_beginthreadex(NULL, 0, &thread_heartbeats, (void*)this, 0, NULL);
	CloseHandle(hHeartBeats);

	return true;
}

bool websoc_client::Poll() { // timeout in milliseconds		
	//fd_set rfds;
	while (true) {
		if (_readyState == CLOSED) {
			return false;
		}
		int N = _rxbuf.size();
		int ret;
		_rxbuf.resize(N + _contentLen);
		ret = SSL_read(_ssl, (char*)&_rxbuf[0] + N, _contentLen);
		//char* ff = (char*)&_rxbuf[0];//for memory test
		//LOG(INFO) << ff;
		if (_readyState == CLOSED) {
			return false;
		}

		if (SSL_get_error(_ssl, ret) == SSL_ERROR_WANT_READ) {
			_rxbuf.resize(N);
			continue;
		}
		else if (ret <= 0) {
			_rxbuf.resize(N);
			_readyState = CLOSED;
			OnError(ret, "Connection error! Connection closed!");
			return false;
		}
		else if(ret > 0){
			_rxbuf.resize(N + ret);
			if (!parse_response()){
				_rxbuf.resize(N + ret);
			}
		}
		else{//receive success.reet rxbuf
			std::vector<uint8_t>().swap(_rxbuf);// free memory
		}
	}

	return true;
}

bool websoc_client::parse_response(){
	// TODO: consider acquiring a lock on rxbuf...
	while (true) {
		wsheader_type ws;
		if (_rxbuf.size() < 2) { return false; /* Need at least 2 */ }
		const uint8_t * data = (uint8_t *)&_rxbuf[0]; // peek, but don't consume
		ws.fin = (data[0] & 0x80) == 0x80;
		ws.opcode = (wsheader_type::opcode_type) (data[0] & 0x0f);
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
			_contentLen = (int)(ws.header_size + ws.N);
			return false; 
			/* Need: ws.header_size+ws.N - rxbuf.size() */
		}

		// We got a whole message, now do something with it:
		if (   ws.opcode == wsheader_type::TEXT_FRAME
			|| ws.opcode == wsheader_type::BINARY_FRAME
			|| ws.opcode == wsheader_type::CONTINUATION
			) {
			_contentLen = 2;//重置cl
			if (ws.mask) { for (size_t i = 0; i != ws.N; ++i) { _rxbuf[i + ws.header_size] ^= ws.masking_key[i & 0x3]; } }
			_receivedData.insert(_receivedData.end(), _rxbuf.begin() + ws.header_size, _rxbuf.begin() + ws.header_size + (size_t)ws.N);// just feed
			if (ws.fin) {
				std::string receivdatas(_receivedData.begin(), _receivedData.end());
				OnMessage(receivdatas);
				_receivedData.erase(_receivedData.begin(), _receivedData.end());
				std::vector<uint8_t>().swap(_receivedData);// free memory
			}
			else{//收到未知的请求参数 fin！=0x8a  视为异常
				OnError(3, "Receive unexpected FIN.Close socket.");
				Close();
			}
		}
		else if (ws.opcode == wsheader_type::PING) {
			LOG(INFO) << "receive ping";
			if (ws.mask) { for (size_t i = 0; i != ws.N; ++i) { _rxbuf[i + ws.header_size] ^= ws.masking_key[i & 0x3]; } }
			std::string data(_rxbuf.begin() + ws.header_size, _rxbuf.begin() + ws.header_size + (size_t)ws.N);
			sendData(wsheader_type::PONG, data.size(), data.begin(), data.end());
		}
		else if (ws.opcode == wsheader_type::PONG) {
			LOG(INFO) << "receive pong";
			SetHbValue(PONG);
		}
		else if (ws.opcode == wsheader_type::CLOSE) { 
			LOG(INFO) << "receive close";
			OnClose();
			_readyState = CLOSED;
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

void websoc_client::SendPing(){
	std::string empty;
	sendData(wsheader_type::PING, empty.size(), empty.begin(), empty.end());

}

void websoc_client::SendPong(){

}

void websoc_client::Close(){
	//Close heartbeat
	_nHbControl = 0;

	if (_readyState == CLOSING || _readyState == CLOSED) { return; }
	_readyState = CLOSING;
	uint8_t closeFrame[6] = { 0x88, 0x80, 0x00, 0x00, 0x00, 0x00 }; // last 4 bytes are a masking key
	std::vector<uint8_t> header(closeFrame, closeFrame + 6);
	_txbuf.insert(_txbuf.end(), header.begin(), header.end());
	int ret = 0;
	while (_txbuf.size()) {
		ret = ::SSL_write(_ssl, (char*)&_txbuf[0], _txbuf.size());
		if (ret > 0) {
			break;
		}
		else if (ret <= 0) {
			_readyState = CLOSED;
			LOG(ERROR) << "Connection error! Connection closed!";
		}

	}
	if (_txbuf.begin() != _txbuf.end() && ret <= (int)_txbuf.size()){
		_txbuf.erase(_txbuf.begin(), _txbuf.begin() + ret);
	}
	std::vector<uint8_t>().swap(_txbuf);// free memory
	_readyState = CLOSED;

	//Sleep(5000);//sleep 5s
	////关闭本次连接
	//if (_ssl){ SSL_shutdown(_ssl); }
	//if (_websocfd != INVALID_SOCKET){
	//	shutdown(_websocfd, SD_BOTH);//强制发送缓冲区未发送的数据并令recv退出
	//	closesocket(_websocfd);
	//}


}

bool websoc_client::sendData(wsheader_type::opcode_type type, uint64_t message_size, std::string::iterator message_begin, std::string::iterator message_end){

	const uint8_t masking_key[4] = { 0x12, 0x34, 0x56, 0x78 };

	if (_readyState == readyStateValues::CLOSING || _readyState == readyStateValues::CLOSED) { return false; }
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
	// N.B. - txbuf will keep growing until it can be transmitted over the socket:
	_txbuf.insert(_txbuf.end(), header.begin(), header.end());
	_txbuf.insert(_txbuf.end(), message_begin, message_end);
	if (_usemask) {
		for (size_t i = 0; i != (size_t)message_size; ++i) { *(_txbuf.end() - message_size + i) ^= masking_key[i & 0x3]; }
	}
	while (_txbuf.size()) {
		int ret = ::SSL_write(_ssl, (char*)&_txbuf[0], _txbuf.size());
		if (ret > 0 && (ret == SSL_ERROR_WANT_WRITE)) {
			continue;
		}
		else if (ret <= 0) {
			_readyState = CLOSED;
			fputs(ret < 0 ? "Connection error!\n" : "Connection closed!\n", stderr);
			return false;
		}
		else {
			_txbuf.erase(_txbuf.begin(), _txbuf.begin() + ret);
		}
	}
	if (!_txbuf.size() && _readyState == CLOSING) {
		_readyState = CLOSED;
	}
	return true;
}

//Virtual
void websoc_client::OnMessage(std::string& sMessage){

}

void websoc_client::OnClose(){

}

void websoc_client::OnError(int nCode, const std::string& sDescription){
	
}



unsigned _stdcall thread_heartbeats(void* arg){
	websoc_client* pWebsoc = (websoc_client*)arg;

	while (pWebsoc->GetHbControl() == 1){

		pWebsoc->SetHbValue(websoc_client::PING);
		pWebsoc->SendPing();
		Sleep(15000);//等待一段时间(15s)后检测服务器是否有返回PONG

		if (pWebsoc->GetHbControl() == 0){
			LOG(INFO) << "loop false,break and close heart thread";
			break;
		}

		if (pWebsoc->GetHbValue() == websoc_client::PING){//等待后未收到服务器PONG消息，视作该链接已经失效，关闭后重建
			LOG(INFO) << "doesnt receive pong message,close connection and break";
			pWebsoc->Close();
			break;
		}

		if (pWebsoc->GetHbControl() == 0){
			LOG(INFO) << "loop false,break and close heart thread";
			break;
		}
		Sleep(30000);//等待x(30s)时间后 ping
	}

	LOG(INFO) << "exit heart thread";
	return 0;
}