#pragma once
// refer to
// https://github.com/dhbaird/easywsclient
//

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <string>
#include <vector>
#include <stdint.h>


#include <openssl\ssl.h>
#include <openssl\err.h>
#include <openssl\bio.h>

#pragma warning(disable:4290)
#pragma warning(disable:4482)


#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib,"libeay32.lib")
#pragma comment(lib,"ssleay32.lib")

#ifdef OPENSSL_USE
#define SocWrite SSL_write
#define SocRead SSL_read
#else
#define SocRead SSL_READ
#endif
#define socketerrno WSAGetLastError()
#define SOCKET_EAGAIN_EINPROGRESS WSAEINPROGRESS
#define SOCKET_EWOULDBLOCK WSAEWOULDBLOCK

// http://tools.ietf.org/html/rfc6455#section-5.2  Base Framing Protocol
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-------+-+-------------+-------------------------------+
// |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
// |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
// |N|V|V|V|       |S|             |   (if payload len==126/127)   |
// | |1|2|3|       |K|             |                               |
// +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
// |     Extended payload length continued, if payload len == 127  |
// + - - - - - - - - - - - - - - - +-------------------------------+
// |                               |Masking-key, if MASK set to 1  |
// +-------------------------------+-------------------------------+
// | Masking-key (continued)       |          Payload Data         |
// +-------------------------------- - - - - - - - - - - - - - - - +
// :                     Payload Data continued ...                :
// + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
// |                     Payload Data continued ...                |
// +---------------------------------------------------------------+
struct wsheader_type {
	unsigned header_size;
	bool fin;
	bool mask;
	enum opcode_type {
		CONTINUATION = 0x0,
		TEXT_FRAME = 0x1,
		BINARY_FRAME = 0x2,
		/*%x3 - 7 are reserved for further non - control frames*/
		CLOSE = 8,
		PING = 9,
		PONG = 0xa,
	} opcode;
	int N0;
	uint64_t N;
	uint8_t masking_key[4];
};


class websoc_client
{
public:
	websoc_client();
	virtual ~websoc_client();


	typedef enum readyStateValues { CLOSING, CLOSED, CONNECTING, OPEN } readyStateValues;

	typedef enum HearbeatsStateValues { PING, PONG} HearbeatsStateValues;

	bool connect();



	/*
	set uri
	*/
	void SetUri(LPCSTR fullurl);

	/*
	close this websocket.send close frame and then close sslsocket.
	*/
	void Close();

	/*
	poll openssl socket.
	*/
	bool Poll();

	/*
	init wsa and openssl env.
	*/
	bool InitEnv();

	/*
	release inner vector buffer
	*/
	void releaseVecbuf();

	/*
	send ping frame.
	*/
	void SendPing();

	/*
	send pong frame.
	*/
	void SendPong();

	int GetHbControl();

	/*
	get heartbeats state
	*/
	HearbeatsStateValues GetHbValue();

	/*
	set heartbeat state
	*/
	void SetHbValue(const HearbeatsStateValues& hbVal);
	/*
	release source
	*/
	bool Uninit();

	virtual void OnMessage(std::string& sMessage);

	virtual void OnClose();

	virtual void OnError(int nCode, const std::string& sDescription);
private:
	/*
	parse respondse.
	*/
	bool parse_response();

	/*
	send data,
	*/
	bool sendData(wsheader_type::opcode_type type, uint64_t message_size, std::string::iterator message_begin, std::string::iterator message_end);




	//variables
	std::string _sUri;//full url
	std::string _host;
	int _port;
	std::string _path;//资源定位

	volatile int _nHbControl;  //控制心跳进程

	int _contentLen;
	CRITICAL_SECTION _cs;
	/*heatbeat to maintain websoc*/
	HearbeatsStateValues _hbVal;

	std::vector<uint8_t> _rxbuf;//read buf
	std::vector<uint8_t> _txbuf;//write buf
	std::vector<uint8_t> _receivedData;

	//websoc_timer _innertimer;
	readyStateValues _readyState;
	bool _usemask;

	/*win socket variables*/
	SOCKET _websocfd;
	WSADATA _wsaData;
	struct addrinfo *addrResult, *ptr, hints;
	/*openssl variables*/
	const SSL_METHOD* _sslmeth;
	SSL_CTX* _sslctx;
	SSL* _ssl;

};

