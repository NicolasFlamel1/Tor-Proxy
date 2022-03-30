// Check if Windows
#ifdef _WIN32

	// Set system version
	#define _WIN32_WINNT _WIN32_WINNT_VISTA
	
	// Use Unicode
	#define UNICODE
	#define _UNICODE
#endif

// Header files
#include <algorithm>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <getopt.h>
#include <iostream>
#include <memory>
#include <random>
#include <signal.h>
#include <sstream>
#include <thread>
#include "event2/buffer.h"
#include "event2/bufferevent_ssl.h"
#include "event2/event.h"
#include "event2/event_struct.h"
#include "event2/http.h"
#include "event2/thread.h"
#include "http-internal.h"
#include "openssl/ssl.h"
#include "openssl/x509v3.h"

// Extern C
extern "C" {

	// Header files
	#include "feature/api/tor_api.h"
	#include "feature/api/tor_api_internal.h"
}

// Check if Windows
#ifdef _WIN32

	// Header files
	#include <ws2tcpip.h>

// Otherwise
#else

	// Header files
	#include <arpa/inet.h>
#endif

using namespace std;


// Definitions

// To string
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

// Check if Windows or macOS
#if defined _WIN32 || defined __APPLE__

	// Quick exit
	#define quick_exit _exit
#endif


// Classes

// Check if Windows
#ifdef _WIN32

	// Windows socket class
	class WindowsSocket final {

		// Public
		public:
		
			// Constructor
			WindowsSocket() {
			
				// Check if initiating Windows socket failed
				WSADATA wsaData;
				if(WSAStartup(MAKEWORD(WindowsSocket::MAJOR_VERSION, WindowsSocket::MINOR_VERSION), &wsaData)) {
				
					// Throw exception
					throw runtime_error("Initiating Windows socket failed");
				}
			}
			
			// Destructor
			~WindowsSocket() {
			
				// Clean up Windows socket
				WSACleanup();
			}
		
		// Private
		private:
		
			// Windows socket major version
			static const BYTE MAJOR_VERSION = 2;
			
			// Windows socket minor version
			static const BYTE MINOR_VERSION = 2;
	};
#endif


// Constants

// Default listen address
static const char *DEFAULT_LISTEN_ADDRESS = "localhost";

// Default listen port
static const uint16_t DEFAULT_LISTEN_PORT = 9060;

// Seconds in a minute
static const int SECONDS_IN_A_MINUTE = 60;

// Minutes in an hour
static const int MINUTES_IN_AN_HOUR = 60;

// Hours in a day
static const int HOURS_IN_A_DAY = 24;

// Microseconds in a millisecond
static const int MICROSECONDS_IN_A_MILLISECOND = 1000;

// Read timeout seconds
static const time_t READ_TIMEOUT_SECONDS = 1 * HOURS_IN_A_DAY * MINUTES_IN_AN_HOUR * SECONDS_IN_A_MINUTE;

// Write timeout seconds
static const time_t WRITE_TIMEOUT_SECONDS = 2 * SECONDS_IN_A_MINUTE;

// No socket
static const evutil_socket_t NO_SOCKET = -1;

// No URI port
static const int NO_URI_PORT = -1;

// HTTP port
static const ev_uint16_t HTTP_PORT = 80;

// HTTPS port
static const ev_uint16_t HTTPS_PORT = 443;

// HTTP bad gateway
static const int HTTP_BAD_GATEWAY = 502;

// HTTP gateway timeout
static const int HTTP_GATEWAY_TIMEOUT = 504;

// Check Tor connected interval microseconds
static const decltype(timeval::tv_usec) CHECK_TOR_CONNECTED_INTERVAL_MICROSECONDS = 100 * MICROSECONDS_IN_A_MILLISECOND;

// Temporary directory length
static const size_t TEMPORARY_DIRECTORY_LENGTH = 8;

// Bytes in a kilobyte
static const int BYTES_IN_A_KILOBYTE = pow(2, 10);

// Kilobytes in a megabyte
static const int KILOBYTE_IN_A_MEGABYTE = BYTES_IN_A_KILOBYTE;

// Maximum headers size
static const size_t MAXIMUM_HEADERS_SIZE = 1 * KILOBYTE_IN_A_MEGABYTE * BYTES_IN_A_KILOBYTE;

// Maximum body size
static const size_t MAXIMUM_BODY_SIZE = 10 * KILOBYTE_IN_A_MEGABYTE * BYTES_IN_A_KILOBYTE;

// SOCKS state
enum class SocksState {

	// Authenticating
	AUTHENTICATING,
	
	// Connecting
	CONNECTING
};


// Global variables

// TLS request index
static int tlsRequestIndex;


// Function prototypes

// Check if Windows
#ifdef _WIN32

	// Add system certificates to certificate store
	static bool addSystemCertificatesToCertificateStore(X509_STORE *certificateStore, const TCHAR *systemStoreName);
#endif


// Main function
int main(int argc, char *argv[]) {

	// Display message
	cout << TOSTRING(PROGRAM_NAME) << " v" << TOSTRING(PROGRAM_VERSION) << endl;
	
	// Initialize no verify
	bool noVerify = false;
	
	// Initialize listen address
	string listenAddress = DEFAULT_LISTEN_ADDRESS;
	
	// Initialize listen port
	uint16_t listenPort = DEFAULT_LISTEN_PORT;
	
	// Initialize certificate
	const char *certificate = nullptr;
	
	// Initialize key
	const char *key = nullptr;
	
	// Set options
	const option options[] = {
	
		// Version
		{"version", no_argument, nullptr, 'v'},
		
		// No verify
		{"no_verify", no_argument, nullptr, 'n'},
		
		// Address
		{"address", required_argument, nullptr, 'a'},
		
		// Port
		{"port", required_argument, nullptr, 'p'},
		
		// Certificate
		{"cert", required_argument, nullptr, 'c'},
		
		// Key
		{"key", required_argument, nullptr, 'k'},
		
		// Help
		{"help", no_argument, nullptr, 'h'},
		
		// End
		{}
	};
	
	// Go through all options
	for(int option = getopt_long(argc, argv, "vna:p:c:k:h", options, nullptr); option != -1; option = getopt_long(argc, argv, "vna:p:c:k:h", options, nullptr)) {
	
		// Check option
		switch(option) {
		
			// Version
			case 'v':
			
				// Return success
				return EXIT_SUCCESS;
		
			// No verify
			case 'n':
			
				// Set no verify
				noVerify = true;
				
				// Break
				break;
			
			// Address
			case 'a':
			
				// Set listen address
				listenAddress = optarg;
				
				// Break
				break;
			
			// Certificate
			case 'c':
			
				// Set certificate
				certificate = optarg;
			
				// Break
				break;
			
			// Key
			case 'k':
			
				// Set key
				key = optarg;
			
				// Break
				break;
			
			// Port
			case 'p':
			
				{
					// Get port
					string port = optarg;
					
					// Check if port is numeric
					if(all_of(port.begin(), port.end(), ::isdigit)) {
					
						// Initialize error occured
						bool errorOccured = false;
					
						// Try
						int portNumber;
						try {
						
							// Get port number from port
							portNumber = stoi(port);
						}
						
						// Catch errors
						catch(...) {
						
							// Set error occured
							errorOccured = true;
						}
						
						// Check if an error didn't occurt
						if(!errorOccured) {
						
							// Check if port number is valid
							if(portNumber >= 1 && portNumber <= UINT16_MAX) {
							
								// Set listen port
								listenPort = portNumber;
						
								// Break
								break;
							}
						}
					}
					
					// Display message
					cout << "Invalid port: " << port << endl;
				}
			
			// Help or default
			case 'h':
			default:
			
				// Display message
				cout << endl << "Usage:" << endl << "\t\"" << argv[0] << "\" [options]" << endl << endl;
				cout << "Options:" << endl;
				cout << "\t-v, --version\t\tDisplays version information" << endl;
				cout << "\t-n, --no_verify\t\tDisables verifying peer when using TLS" << endl;
				cout << "\t-a, --address\t\tSets address to listen on" << endl;
				cout << "\t-p, --port\t\tSets port to listen on" << endl;
				cout << "\t-c, --cert\t\tSets the TLS certificate file" << endl;
				cout << "\t-k, --key\t\tSets the TLS private key file" << endl;
				cout << "\t-h, --help\t\tDisplays help information" << endl;
			
				// Return failure
				return EXIT_FAILURE;
		}
	}
	
	// Check if certificate is provided without a key or a key is provided without a certificate
	if((certificate && !key) || (!certificate && key)) {
	
		// Display message
		cout << ((certificate && !key) ? "No key provided for the certificate" : "No certificate provided for the key") << endl;
		
		// Display message
		cout << endl << "Usage:" << endl << "\t\"" << argv[0] << "\" [options]" << endl << endl;
		cout << "Options:" << endl;
		cout << "\t-v, --version\t\tDisplays version information" << endl;
		cout << "\t-n, --no_verify\t\tDisables verifying peer when using TLS" << endl;
		cout << "\t-a, --address\t\tSets address to listen on" << endl;
		cout << "\t-p, --port\t\tSets port to listen on" << endl;
		cout << "\t-c, --cert\t\tSets the TLS certificate file" << endl;
		cout << "\t-k, --key\t\tSets the TLS private key file" << endl;
		cout << "\t-h, --help\t\tDisplays help information" << endl;
	
		// Return failure
		return EXIT_FAILURE;
	}
	
	// Set using TLS server to if a certificate and key are provided
	const bool usingTlsServer = certificate && key;

	// Check if not Windows
	#ifndef _WIN32

		// Check if blocking all signals failed
		sigset_t signalMask;
		if(sigfillset(&signalMask) || pthread_sigmask(SIG_BLOCK, &signalMask, nullptr)) {
		
			// Display message
			cout << "Blocking all signals failed" << endl;
		
			// Return failure
			return EXIT_FAILURE;
		}
	#endif
	
	// Check if Windows
	#ifdef _WIN32
	
		// Check if enabling thread support failed
		if(evthread_use_windows_threads()) {
		
			// Display message
			cout << "Enabling thread support failed" << endl;
		
			// Return failure
			return EXIT_FAILURE;
		}
	
	// Otherwise
	#else

		// Check if enabling thread support failed
		if(evthread_use_pthreads()) {
		
			// Display message
			cout << "Enabling thread support failed" << endl;
		
			// Return failure
			return EXIT_FAILURE;
		}
	#endif
	
	// Check if Windows
	#ifdef _WIN32
	
		// Initialize Windows socket
		unique_ptr<WindowsSocket> windowsSocket;
		
		// Try
		try {
		
			// Set Windows socket
			windowsSocket = make_unique<WindowsSocket>();
		}
		
		// Catch errors
		catch(const runtime_error &error) {
		
			// Display message
			cout << error.what() << endl;
		
			// Return failure
			return EXIT_FAILURE;
		}
	#endif

	// Check if creating TLS method failed
	const SSL_METHOD *tlsMethod = TLS_method();
	if(!tlsMethod) {
	
		// Display message
		cout << "Creating TLS method failed" << endl;
	
		// Return failure
		return EXIT_FAILURE;
	}
	
	// Check if creating TLS context failed
	unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> tlsContext(SSL_CTX_new(tlsMethod), SSL_CTX_free);
	if(!tlsContext) {
	
		// Display message
		cout << "Creating TLS context failed" << endl;
	
		// Return failure
		return EXIT_FAILURE;
	}
	
	// Check if Windows
	#ifdef _WIN32
	
		// Check if getting TLS context's certificate store failed
		X509_STORE *certificateStore = SSL_CTX_get_cert_store(tlsContext.get());
		if(!certificateStore) {
		
			// Display message
			cout << "Getting TLS context's certificate store failed" << endl;
		
			// Return failure
			return EXIT_FAILURE;
		}
		
		// Check if adding system certificates to the certificate store failed
		if(!addSystemCertificatesToCertificateStore(certificateStore, TEXT("ROOT")) || !addSystemCertificatesToCertificateStore(certificateStore, TEXT("CA")) || !addSystemCertificatesToCertificateStore(certificateStore, TEXT("MY"))) {
		
			// Display message
			cout << "Adding system certificates to the certificate store failed" << endl;
		
			// Return failure
			return EXIT_FAILURE;
		}
	
	// Otherwise
	#else
	
		// Check if using the default verify paths for the TLS context failed
		if(!SSL_CTX_set_default_verify_paths(tlsContext.get())) {
		
			// Display message
			cout << "Using the default verify paths for the TLS context failed" << endl;
		
			// Return failure
			return EXIT_FAILURE;
		}
	#endif
	
	// Check if creating TLS request index failed
	tlsRequestIndex = SSL_get_ex_new_index(0, const_cast<char *>("request index"), nullptr, nullptr, nullptr);
	if(tlsRequestIndex == -1) {
	
		// Display message
		cout << "Creating TLS request index failed" << endl;
	
		// Return failure
		return EXIT_FAILURE;
	}
	
	// Check if using TLS server
	if(usingTlsServer) {
	
		// Check if setting the TLS context's certificate and key failed
		if(SSL_CTX_use_certificate_chain_file(tlsContext.get(), certificate) != 1 || SSL_CTX_use_PrivateKey_file(tlsContext.get(), key, SSL_FILETYPE_PEM) != 1 || SSL_CTX_check_private_key(tlsContext.get()) != 1) {
		
			// Display message
			cout << "Setting the TLS context's certificate and key failed" << endl;
		
			// Return failure
			return EXIT_FAILURE;
		}
	}
	
	// Check if creating event base failed
	shared_ptr<event_base> eventBase(event_base_new(), event_base_free);
	if(!eventBase) {
	
		// Display message
		cout << "Creating event base failed" << endl;
	
		// Return failure
		return EXIT_FAILURE;
	}
	
	// Check if creating HTTP server failed
	unique_ptr<evhttp, decltype(&evhttp_free)> httpServer(evhttp_new(eventBase.get()), evhttp_free);
	if(!httpServer) {
	
		// Display message
		cout << "Creating HTTP server failed" << endl;
	
		// Return failure
		return EXIT_FAILURE;
	}
	
	// Set HTTP server's maximum header size
	evhttp_set_max_headers_size(httpServer.get(), MAXIMUM_HEADERS_SIZE);
	
	// Set HTTP server's maximum body size
	evhttp_set_max_body_size(httpServer.get(), MAXIMUM_BODY_SIZE);
	
	// Set HTTP server to allow all types of requests
	evhttp_set_allowed_methods(httpServer.get(), EVHTTP_REQ_GET | EVHTTP_REQ_POST | EVHTTP_REQ_HEAD | EVHTTP_REQ_PUT | EVHTTP_REQ_DELETE | EVHTTP_REQ_OPTIONS | EVHTTP_REQ_TRACE | EVHTTP_REQ_CONNECT | EVHTTP_REQ_PATCH);
	
	// Check if using TLS server
	if(usingTlsServer) {
	
		// Set HTTP server buffer event create callback
		evhttp_set_bevcb(httpServer.get(), ([](event_base *eventBase, void *argument) -> bufferevent * {
		
			// Get TLS context from argument
			SSL_CTX *tlsContext = reinterpret_cast<SSL_CTX *>(argument);
		
			// Check if creating TLS connection from the TLS context failed
			unique_ptr<SSL, decltype(&SSL_free)> tlsConnection(SSL_new(tlsContext), SSL_free);
			if(!tlsConnection) {
			
				// Return null
				return nullptr;
			}
			
			// Check if creating TLS buffer failed
			unique_ptr<bufferevent, decltype(&bufferevent_free)> tlsBuffer(bufferevent_openssl_socket_new(eventBase, NO_SOCKET, tlsConnection.get(), BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS), bufferevent_free);
			if(!tlsBuffer) {
			
				// Return null
				return nullptr;
			}
			
			// Release TLS connection
			tlsConnection.release();
			
			// Get buffer event
			bufferevent *bufferEvent = tlsBuffer.get();
			
			// Release TLS buffer
			tlsBuffer.release();
			
			// Return buffer event
			return bufferEvent;
			
		}), tlsContext.get());
	}
	
	// Initialize Tor address
	string torAddress;
	
	// Initialize Tor port
	uint16_t torPort;
	
	// Initialize HTTP server request callback argument
	tuple<const bool *, const string *, const uint16_t *, const bool *, SSL_CTX *, const string *, const uint16_t *> httpServerRequestCallbackArgument(&noVerify, &listenAddress, &listenPort, &usingTlsServer, tlsContext.get(), &torAddress, &torPort);
	
	// Set HTTP server request callback
	evhttp_set_gencb(httpServer.get(), ([](evhttp_request *request, void *argument) {
	
		// Get HTTP server request callback argument from argument
		tuple<const bool *, const string *, const uint16_t *, const bool *, SSL_CTX *, string *, uint16_t *> *httpServerRequestCallbackArgument = reinterpret_cast<tuple<const bool *, const string *, const uint16_t *, const bool *, SSL_CTX *, string *, uint16_t *> *>(argument);
		
		// Get no verify from HTTP server request callback argument
		const bool *noVerify = get<0>(*httpServerRequestCallbackArgument);
		
		// Get listen address from HTTP server request callback argument
		const string *listenAddress = get<1>(*httpServerRequestCallbackArgument);
		
		// Get listen port from HTTP server request callback argument
		const uint16_t *listenPort = get<2>(*httpServerRequestCallbackArgument);
		
		// Get using TLS server from HTTP server request callback argument
		const bool *usingTlsServer = get<3>(*httpServerRequestCallbackArgument);
		
		// Get TLS context from HTTP server request callback argument
		SSL_CTX *tlsContext = get<4>(*httpServerRequestCallbackArgument);
	
		// Get Tor address from HTTP server request callback argument
		const string *torAddress = get<5>(*httpServerRequestCallbackArgument);
		
		// Get Tor port from HTTP server request callback argument
		const uint16_t *torPort = get<6>(*httpServerRequestCallbackArgument);
		
		// Check if using TLS server
		if(*usingTlsServer) {
		
			// Set request's connection close callback
			evhttp_connection_set_closecb(evhttp_request_get_connection(request), ([](evhttp_connection *connection, void *argument) {
			
				// Check if request's buffer event exists
				bufferevent *bufferEvent = evhttp_connection_get_bufferevent(connection);
				if(bufferEvent) {
			
					// Check if request's TLS connection exists
					SSL *requestTlsConnection = bufferevent_openssl_get_ssl(bufferEvent);
					if(requestTlsConnection) {
					
						// Shutdown request's TLS connection
						SSL_shutdown(requestTlsConnection);
					}
				}
				
			}), nullptr);
		}
		
		// Check if request doesn't have a URI
		if(!evhttp_request_get_uri(request) || !strlen(evhttp_request_get_uri(request))) {
		
			// Reply with bad request error to request
			evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
		}
		
		// Otherwise
		else {
	
			// Check if parsing request's URI failed
			unique_ptr<evhttp_uri, decltype(&evhttp_uri_free)> uri(evhttp_uri_parse(&evhttp_request_get_uri(request)[sizeof('/')]), evhttp_uri_free);
			if(!uri) {
			
				// Reply with bad request error to request
				evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
			}
			
			// Otherwise check if URI doesn't have a host or its host is invalid
			else if(!evhttp_uri_get_host(uri.get()) || !strlen(evhttp_uri_get_host(uri.get())) || strlen(evhttp_uri_get_host(uri.get())) > UINT8_MAX) {
			
				// Reply with bad request error to request
				evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
			}
			
			// Otherwise check if URI's scheme isn't supported
			else if(evhttp_uri_get_scheme(uri.get()) && strcasecmp(evhttp_uri_get_scheme(uri.get()), "http") && strcasecmp(evhttp_uri_get_scheme(uri.get()), "https")) {
			
				// Reply with bad request error to request
				evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
			}
			
			// Otherwise
			else {
			
				// Check if creating SOCKS buffer failed
				unique_ptr<bufferevent, decltype(&bufferevent_free)> socksBuffer(bufferevent_socket_new(evhttp_connection_get_base(evhttp_request_get_connection(request)), NO_SOCKET, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS), bufferevent_free);
				if(!socksBuffer) {
				
					// Reply with internal server error to request
					evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
				}
				
				// Otherwise
				else {
				
					// Set read timeout
					const timeval readTimeout = {
					
						// Seconds
						.tv_sec = READ_TIMEOUT_SECONDS
					};
				
					// Set write timeout
					const timeval writeTimeout = {
					
						// Seconds
						.tv_sec = WRITE_TIMEOUT_SECONDS
					};
				
					// Set SOCKS buffer's read and write timeout
					bufferevent_set_timeouts(socksBuffer.get(), &readTimeout, &writeTimeout);
					
					// Check if creating SOCKS state failed
					unique_ptr<SocksState> socksState = make_unique<SocksState>(SocksState::AUTHENTICATING);
					if(!socksState) {
					
						// Reply with internal server error to request
						evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
					}
					
					// Otherwise
					else {
				
						// Check if creating SOCKS buffer callbacks argument failed
						unique_ptr<tuple<evhttp_request *, const bool *, const string *, const uint16_t *, const bool *, SSL_CTX *, const string *, const uint16_t *, evhttp_uri *, SocksState *>> socksBufferCallbacksArgument = make_unique<tuple<evhttp_request *, const bool *, const string *, const uint16_t *, const bool *, SSL_CTX *, const string *, const uint16_t *, evhttp_uri *, SocksState *>>(request, noVerify, listenAddress, listenPort, usingTlsServer, tlsContext, torAddress, torPort, uri.get(), socksState.get());
						if(!socksBufferCallbacksArgument) {
						
							// Reply with internal server error to request
							evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
						}
						
						// Otherwise
						else {
						
							// Set SOCKS buffer callbacks
							bufferevent_setcb(socksBuffer.get(), ([](bufferevent *buffer, void *argument) {
							
								// Get SOCKS buffer from buffer
								unique_ptr<bufferevent, decltype(&bufferevent_free)> socksBuffer(buffer, bufferevent_free);
							
								// Get SOCKS buffer callbacks argument from argument
								unique_ptr<tuple<evhttp_request *, const bool *, const string *, const uint16_t *, const bool *, SSL_CTX *, const string *, const uint16_t *, evhttp_uri *, SocksState *>> socksBufferCallbacksArgument(reinterpret_cast<tuple<evhttp_request *, const bool *, const string *, const uint16_t *, const bool *, SSL_CTX *, const string *, const uint16_t *, evhttp_uri *, SocksState *> *>(argument));
								
								// Get request from SOCKS buffer callbacks argument
								evhttp_request *request = get<0>(*socksBufferCallbacksArgument);
								
								// Get no verify from SOCKS buffer callbacks argument
								const bool *noVerify = get<1>(*socksBufferCallbacksArgument);
								
								// Get listen address from SOCKS buffer callbacks argument
								const string *listenAddress = get<2>(*socksBufferCallbacksArgument);
								
								// Get listen port from SOCKS buffer callbacks argument
								const uint16_t *listenPort = get<3>(*socksBufferCallbacksArgument);
								
								// Get using TLS server from SOCKS buffer callbacks argument
								const bool *usingTlsServer = get<4>(*socksBufferCallbacksArgument);
								
								// Get TLS context from SOCKS buffer callbacks argument
								SSL_CTX *tlsContext = get<5>(*socksBufferCallbacksArgument);
								
								// Get Tor address from SOCKS buffer callbacks argument
								const string *torAddress = get<6>(*socksBufferCallbacksArgument);
								
								// Get Tor port from SOCKS buffer callbacks argument
								const uint16_t *torPort = get<7>(*socksBufferCallbacksArgument);
								
								// Get URI from SOCKS buffer callbacks argument
								unique_ptr<evhttp_uri, decltype(&evhttp_uri_free)> uri(get<8>(*socksBufferCallbacksArgument), evhttp_uri_free);
								
								// Get SOCKS state from SOCKS buffer callbacks argument
								unique_ptr<SocksState> socksState(get<9>(*socksBufferCallbacksArgument));
								
								// Check if getting input from the SOCKS buffer failed
								evbuffer *input = bufferevent_get_input(socksBuffer.get());
								if(!input) {
								
									// Remove SOCKS buffer callbacks
									bufferevent_setcb(socksBuffer.get(), nullptr, nullptr, nullptr, nullptr);
								
									// Reply with internal server error to request
									evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
								}
								
								// Otherwise
								else {
								
									// Get input's length
									const size_t length = evbuffer_get_length(input);
									
									// Check if getting data from input failed
									uint8_t data[length];
									if(evbuffer_copyout(input, data, length) == -1) {
									
										// Remove data from input
										evbuffer_drain(input, length);
									
										// Remove SOCKS buffer callbacks
										bufferevent_setcb(socksBuffer.get(), nullptr, nullptr, nullptr, nullptr);
									
										// Reply with internal server error to request
										evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
									}
									
									// Otherwise check if removing data from input failed
									else if(evbuffer_drain(input, length)) {
									
										// Remove SOCKS buffer callbacks
										bufferevent_setcb(socksBuffer.get(), nullptr, nullptr, nullptr, nullptr);
									
										// Reply with internal server error to request
										evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
									}
									
									// Otherwise
									else {
										
										// Check SOCKS state
										switch(*socksState) {
										
											// Authenticating
											case SocksState::AUTHENTICATING:
											
												// Check if response isn't complete
												if(length != sizeof("\x05\x00") - sizeof('\0')) {
												
													// Remove SOCKS buffer callbacks
													bufferevent_setcb(socksBuffer.get(), nullptr, nullptr, nullptr, nullptr);
												
													// Reply with internal server error to request
													evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
												}
												
												// Otherwise check if authentication method isn't supported
												else if(data[1] != 0) {
												
													// Remove SOCKS buffer callbacks
													bufferevent_setcb(socksBuffer.get(), nullptr, nullptr, nullptr, nullptr);
												
													// Reply with internal server error to request
													evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
												}
												
												// Otherwise
												else {
												
													// Get host
													const string host = evhttp_uri_get_host(uri.get());
												
													// Get port
													const uint16_t port = htons((evhttp_uri_get_port(uri.get()) != NO_URI_PORT) ? evhttp_uri_get_port(uri.get()) : (evhttp_uri_get_scheme(uri.get()) && !strcasecmp(evhttp_uri_get_scheme(uri.get()), "https")) ? HTTPS_PORT : HTTP_PORT);
												
													// Set connection request
													uint8_t connectionRequest[sizeof("\x05\x01\x00\x03") - sizeof('\0') + sizeof(uint8_t) + host.length() + sizeof(port)];
													
													// Set connection request's information							
													memcpy(connectionRequest, "\x05\x01\x00\x03", sizeof("\x05\x01\x00\x03") - sizeof('\0'));
													
													// Set connection request's host length
													connectionRequest[sizeof("\x05\x01\x00\x03") - sizeof('\0')] = host.length();
													
													// Set connection request's host
													memcpy(&connectionRequest[sizeof("\x05\x01\x00\x03") - sizeof('\0') + sizeof(uint8_t)], host.c_str(), host.length());
													
													// Set connection request's port
													memcpy(&connectionRequest[sizeof("\x05\x01\x00\x03") - sizeof('\0') + sizeof(uint8_t) + host.length()], &port, sizeof(port));
													
													// Check if sending connection requests to the SOCKS proxy failed
													if(bufferevent_write(socksBuffer.get(), connectionRequest, sizeof(connectionRequest))) {
													
														// Remove SOCKS buffer callbacks
														bufferevent_setcb(socksBuffer.get(), nullptr, nullptr, nullptr, nullptr);
													
														// Reply with internal server error to request
														evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
													}
													
													else {
													
														// Set SOCKS state to connecting
														*socksState = SocksState::CONNECTING;
														
														// Release SOCKS buffer
														socksBuffer.release();
														
														// Release SOCKS buffer callbacks argument
														socksBufferCallbacksArgument.release();
													
														// Release URI
														uri.release();
													
														// Release SOCKS state
														socksState.release();
													}
												}
											
												// Break
												break;
											
											// Connecting
											case SocksState::CONNECTING:
											
												// Check if response isn't complete
												if(length != sizeof("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00") - sizeof('\0')) {
												
													// Remove SOCKS buffer callbacks
													bufferevent_setcb(socksBuffer.get(), nullptr, nullptr, nullptr, nullptr);
												
													// Reply with internal server error to request
													evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
												}
												
												// Otherwise check if connection failed
												else if(data[1] != 0) {
												
													// Remove SOCKS buffer callbacks
													bufferevent_setcb(socksBuffer.get(), nullptr, nullptr, nullptr, nullptr);
												
													// Reply with bad gateway error to request
													evhttp_send_reply(request, HTTP_BAD_GATEWAY, nullptr, nullptr);
												}
												
												// Otherwise
												else {
												
													// Remove SOCKS buffer callbacks
													bufferevent_setcb(socksBuffer.get(), nullptr, nullptr, nullptr, nullptr);
													
													// Check if destination is using HTTPS
													if(evhttp_uri_get_scheme(uri.get()) && !strcasecmp(evhttp_uri_get_scheme(uri.get()), "https")) {
													
														// Check if creating TLS connection from the TLS context failed
														unique_ptr<SSL, decltype(&SSL_free)> tlsConnection(SSL_new(tlsContext), SSL_free);
														if(!tlsConnection) {
														
															// Reply with internal server error to request
															evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
														}
														
														// Otherwise
														else {
														
															// Check if enabling the TLS connection's hostname checking failed
															SSL_set_hostflags(tlsConnection.get(), X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
															
															if(!SSL_set1_host(tlsConnection.get(), evhttp_uri_get_host(uri.get()))) {
															
																// Reply with internal server error to request
																evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
															}
															
															// Otherwise
															else {
															
																// Check if setting the TLS connection's server name indication failed
																if(!SSL_set_tlsext_host_name(tlsConnection.get(), evhttp_uri_get_host(uri.get()))) {
																
																	// Reply with internal server error to request
																	evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																}
																
																// Otherwise
																else {
																
																	// Check if creating TLS buffer failed
																	unique_ptr<bufferevent, decltype(&bufferevent_free)> tlsBuffer(bufferevent_openssl_filter_new(bufferevent_get_base(socksBuffer.get()), socksBuffer.get(), tlsConnection.get(), BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS), bufferevent_free);
																	if(!tlsBuffer) {
																	
																		// Reply with internal server error to request
																		evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																	}
																	
																	// Otherwise
																	else {
																	
																		// Release SOCKS buffer
																		socksBuffer.release();
																	
																		// Release TLS connection
																		tlsConnection.release();
																		
																		// Allow dirty shutdown for the TLS buffer
																		bufferevent_openssl_set_allow_dirty_shutdown(tlsBuffer.get(), true);
																	
																		// Set read timeout
																		const timeval readTimeout = {
																		
																			// Seconds
																			.tv_sec = READ_TIMEOUT_SECONDS
																		};
																	
																		// Set write timeout
																		const timeval writeTimeout = {
																		
																			// Seconds
																			.tv_sec = WRITE_TIMEOUT_SECONDS
																		};
																	
																		// Set STLS buffer's read and write timeout
																		bufferevent_set_timeouts(tlsBuffer.get(), &readTimeout, &writeTimeout);
																		
																		// Check if creating SOCKS connection failed
																		unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)> socksConnection(evhttp_connection_base_bufferevent_new(bufferevent_get_base(tlsBuffer.get()), nullptr, tlsBuffer.get(), torAddress->c_str(), *torPort), evhttp_connection_free);
																		if(!socksConnection) {
																		
																			// Reply with internal server error to request
																			evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																		}
																		
																		// Otherwise
																		else {
																		
																			// Release TLS buffer
																			tlsBuffer.release();
																		
																			// Set that SOCKS connection is connected
																			socksConnection->state = EVCON_IDLE;
																			
																			// Check if creating request finished failed
																			unique_ptr<bool> requestFinished = make_unique<bool>(false);
																			if(!requestFinished) {
																			
																				// Reply with internal server error to request
																				evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																			}
																			
																			// Otherwise
																			else {
																			
																				// Check if creating outgoing request callback argument failed
																				unique_ptr<tuple<evhttp_request *, const bool *, const string *, const uint16_t *, const bool *, evhttp_uri *, evhttp_connection *, bool *>> outgoingRequestCallbackArgument = make_unique<tuple<evhttp_request *, const bool *, const string *, const uint16_t *, const bool *, evhttp_uri *, evhttp_connection *, bool *>>(request, noVerify, listenAddress, listenPort, usingTlsServer, uri.get(), socksConnection.get(), requestFinished.get());
																				if(!outgoingRequestCallbackArgument) {
																				
																					// Reply with internal server error to request
																					evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																				}
																				
																				// Otherwise
																				else {
																		
																					// Check if creating outgoing request failed
																					unique_ptr<evhttp_request, decltype(&evhttp_request_free)> outgoingRequest(evhttp_request_new(([](evhttp_request *outgoingRequest, void *argument) {
																					
																						// Get outgoing request callback argument from argument
																						unique_ptr<tuple<evhttp_request *, const bool *, const string *, const uint16_t *, const bool *, evhttp_uri *, evhttp_connection *, bool *>> outgoingRequestCallbackArgument(reinterpret_cast<tuple<evhttp_request *, const bool *, const string *, const uint16_t *, const bool *, evhttp_uri *, evhttp_connection *, bool *> *>(argument));
																						
																						// Get request from outgoing request callback argument
																						evhttp_request *request = get<0>(*outgoingRequestCallbackArgument);
																						
																						// Get no verify from outgoing request callback argument
																						const bool *noVerify = get<1>(*outgoingRequestCallbackArgument);
																						
																						// Get listen address from outgoing request callback argument
																						const string *listenAddress = get<2>(*outgoingRequestCallbackArgument);
																						
																						// Get listen port from outgoing request callback argument
																						const uint16_t *listenPort = get<3>(*outgoingRequestCallbackArgument);
																						
																						// Get using TLS server from outgoing request callback argument
																						const bool *usingTlsServer = get<4>(*outgoingRequestCallbackArgument);
																						
																						// Get URI from outgoing request callback argument
																						unique_ptr<evhttp_uri, decltype(&evhttp_uri_free)> uri(get<5>(*outgoingRequestCallbackArgument), evhttp_uri_free);
																						
																						// Get SOCKS connection from outgoing request callback argument
																						unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)> socksConnection(get<6>(*outgoingRequestCallbackArgument), evhttp_connection_free);
																						
																						// Get request finished from outgoing request callback argument
																						unique_ptr<bool> requestFinished(get<7>(*outgoingRequestCallbackArgument));
																						
																						// Check if outgoing request exists
																						if(outgoingRequest) {
																						
																							// Remove outgoing request error callback
																							evhttp_request_set_error_cb(outgoingRequest, nullptr);
																						
																							// Get TLS connection
																							SSL *tlsConnection = bufferevent_openssl_get_ssl(evhttp_connection_get_bufferevent(evhttp_request_get_connection(outgoingRequest)));
																							
																							// Check if request isn't finished
																							if(!*requestFinished) {
																							
																								// Initialize TLS verified
																								bool tlsVerified = *noVerify;
																								
																								// Check if TLS connection was verified
																								if(tlsConnection && SSL_get_peer_certificate(tlsConnection) && SSL_get_verify_result(tlsConnection) == X509_V_OK && SSL_get0_peername(tlsConnection)) {
																								
																									// Set TLS verified
																									tlsVerified = true;
																								}
																								
																								// Check if TLS was verified and outgoing request was successful
																								if(tlsVerified && evhttp_request_get_response_code(outgoingRequest)) {
																								
																									// Check if response to the request hasn't been started
																									if(!evhttp_request_get_response_code(request)) {
																									
																										// Initialize error occured
																										bool errorOccured = false;
																									
																										// Check if outgoing request has headers
																										evkeyvalq *headers = evhttp_request_get_input_headers(outgoingRequest);
																										if(headers) {
																										
																											// Go through all of the outgoing request's headers
																											for(evkeyval *header = headers->tqh_first; header; header = header->next.tqe_next) {
																											
																												// Check if header is a location or refresh header
																												if(!strcasecmp(header->key, "Location") || !strcasecmp(header->key, "Refresh")) {
																												
																													// Initialize value
																													string value;
																													
																													// Check if listen address is an IPv6 address
																													char temp[sizeof(in6_addr)];
																													if(inet_pton(AF_INET6, listenAddress->c_str(), temp) == 1) {
																													
																														// Set value
																														value = string(*usingTlsServer ? "https" : "http") + "://[" + *listenAddress + "]:" + to_string(*listenPort) + '/' + header->value;
																													}
																													
																													// Otherwise
																													else {
																												
																														// Set value
																														value = string(*usingTlsServer ? "https" : "http") + "://" + *listenAddress + ':' + to_string(*listenPort) + '/' + header->value;
																													}
																													
																													// Check if setting request's header to the header with the value failed
																													if(evhttp_add_header(evhttp_request_get_output_headers(request), header->key, value.c_str())) {
																													
																														// Set error occured
																														errorOccured = true;
																													
																														// Remove all request headers
																														evhttp_clear_headers(evhttp_request_get_output_headers(request));
																														
																														// Reply with internal server error to request
																														evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																													}
																												}
																												
																												// Otherwise
																												else {
																											
																													// Check if setting request's header to the header failed
																													if(evhttp_add_header(evhttp_request_get_output_headers(request), header->key, header->value)) {
																													
																														// Set error occured
																														errorOccured = true;
																													
																														// Remove all request headers
																														evhttp_clear_headers(evhttp_request_get_output_headers(request));
																														
																														// Reply with internal server error to request
																														evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																													}
																												}
																											}
																										}
																										
																										// Check if an error didn't occur
																										if(!errorOccured) {
																									
																											// Set request's outgoing data to be the outgoing request's incomming data
																											evbuffer_add_buffer(evhttp_request_get_output_buffer(request), evhttp_request_get_input_buffer(outgoingRequest));
																											
																											// Reply with respone to request
																											evhttp_send_reply(request, evhttp_request_get_response_code(outgoingRequest), nullptr, nullptr);
																										}
																									}
																									
																									// Otherwise
																									else {
																									
																										// Reply with chunk to the request
																										evhttp_send_reply_chunk(request, evhttp_request_get_input_buffer(outgoingRequest));
																										
																										// End reply with the request request
																										evhttp_send_reply_end(request);
																									}
																								}
																								
																								// Otherwise
																								else {
																								
																									// Remove all request headers
																									evhttp_clear_headers(evhttp_request_get_output_headers(request));
																								
																									// Reply with bad gateway error to request
																									evhttp_send_reply(request, HTTP_BAD_GATEWAY, nullptr, nullptr);
																								}
																							}
																							
																							// Check if TLS connection exists
																							if(tlsConnection) {
																							
																								// Shutdown TLS connection
																								SSL_shutdown(tlsConnection);
																							}
																							
																							// Cancel outgoing request
																							evhttp_cancel_request(outgoingRequest);
																							
																							// Free outgoing request
																							evhttp_request_free(outgoingRequest);
																						}
																						
																						// Otherwise check if request isn't finished
																						else if(!*requestFinished) {
																						
																							// Remove all request headers
																							evhttp_clear_headers(evhttp_request_get_output_headers(request));
																						
																							// Reply with bad gateway error to request
																							evhttp_send_reply(request, HTTP_BAD_GATEWAY, nullptr, nullptr);
																						}
																						
																					}), outgoingRequestCallbackArgument.get()), evhttp_request_free);
																					
																					if(!outgoingRequest) {
																					
																						// Reply with internal server error to request
																						evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																					}
																					
																					// Otherwise
																					else {
																					
																						// Set outgoing request chunk callback
																						evhttp_request_set_chunked_cb(outgoingRequest.get(), ([](evhttp_request *outgoingRequest, void *argument) {
																						
																							// Get outgoing request callback argument from argument
																							unique_ptr<tuple<evhttp_request *, const bool *, const string *, const uint16_t *, const bool *, evhttp_uri *, evhttp_connection *, bool *>> outgoingRequestCallbackArgument(reinterpret_cast<tuple<evhttp_request *, const bool *, const string *, const uint16_t *, const bool *, evhttp_uri *, evhttp_connection *, bool *> *>(argument));
																							
																							// Get request from outgoing request callback argument
																							evhttp_request *request = get<0>(*outgoingRequestCallbackArgument);
																							
																							// Get no verify from outgoing request callback argument
																							const bool *noVerify = get<1>(*outgoingRequestCallbackArgument);
																							
																							// Get listen address from outgoing request callback argument
																							const string *listenAddress = get<2>(*outgoingRequestCallbackArgument);
																							
																							// Get listen port from outgoing request callback argument
																							const uint16_t *listenPort = get<3>(*outgoingRequestCallbackArgument);
																							
																							// Get using TLS server from outgoing request callback argument
																							const bool *usingTlsServer = get<4>(*outgoingRequestCallbackArgument);
																							
																							// Get request finished from outgoing request callback argument
																							unique_ptr<bool> requestFinished(get<7>(*outgoingRequestCallbackArgument));
																							
																							// Get TLS connection
																							SSL *tlsConnection = bufferevent_openssl_get_ssl(evhttp_connection_get_bufferevent(evhttp_request_get_connection(outgoingRequest)));
																							
																							// Check if request isn't finished
																							if(!*requestFinished) {
																						
																								// Initialize TLS verified
																								bool tlsVerified = *noVerify;
																								
																								// Check if TLS connection was verified
																								if(tlsConnection && SSL_get_peer_certificate(tlsConnection) && SSL_get_verify_result(tlsConnection) == X509_V_OK && SSL_get0_peername(tlsConnection)) {
																								
																									// Set TLS verified
																									tlsVerified = true;
																								}
																								
																								// Check if TLS was verified and outgoing request was successful
																								if(tlsVerified && outgoingRequest && evhttp_request_get_response_code(outgoingRequest)) {
																								
																									// Check if response to the request hasn't been started
																									if(!evhttp_request_get_response_code(request)) {
																									
																										// Check if outgoing request has headers
																										evkeyvalq *headers = evhttp_request_get_input_headers(outgoingRequest);
																										if(headers) {
																										
																											// Go through all of the outgoing request's headers
																											for(evkeyval *header = headers->tqh_first; header; header = header->next.tqe_next) {
																											
																												// Check if header is a location or refresh header
																												if(!strcasecmp(header->key, "Location") || !strcasecmp(header->key, "Refresh")) {
																												
																													// Initialize value
																													string value;
																													
																													// Check if listen address is an IPv6 address
																													char temp[sizeof(in6_addr)];
																													if(inet_pton(AF_INET6, listenAddress->c_str(), temp) == 1) {
																													
																														// Set value
																														value = string(*usingTlsServer ? "https" : "http") + "://[" + *listenAddress + "]:" + to_string(*listenPort) + '/' + header->value;
																													}
																													
																													// Otherwise
																													else {
																												
																														// Set value
																														value = string(*usingTlsServer ? "https" : "http") + "://" + *listenAddress + ':' + to_string(*listenPort) + '/' + header->value;
																													}
																													
																													// Check if setting request's header to the header with the value failed
																													if(evhttp_add_header(evhttp_request_get_output_headers(request), header->key, value.c_str())) {
																													
																														// Remove all request headers
																														evhttp_clear_headers(evhttp_request_get_output_headers(request));
																														
																														// Reply with internal server error to request
																														evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																														
																														// Set that request is finished
																														*requestFinished = true;
																														
																														// Release request finished
																														requestFinished.release();
																														
																														// Release outgoing request callback argument
																														outgoingRequestCallbackArgument.release();
																														
																														// Return
																														return;
																													}
																												}
																												
																												// Otherwise check if header isn't chunked transfer encoding
																												else if(strcasecmp(header->key, "Transfer-Encoding") || strcasecmp(header->value, "chunked")) {
																											
																													// Check if setting request's header to the header failed
																													if(evhttp_add_header(evhttp_request_get_output_headers(request), header->key, header->value)) {
																													
																														// Remove all request headers
																														evhttp_clear_headers(evhttp_request_get_output_headers(request));
																													
																														// Reply with internal server error to request
																														evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																														
																														// Set that request is finished
																														*requestFinished = true;
																														
																														// Release outgoing request callback argument
																														outgoingRequestCallbackArgument.release();
																														
																														// Release request finished
																														requestFinished.release();
																														
																														// Return
																														return;
																													}
																												}
																											}
																										}
																									
																										// Start reply to the request
																										evhttp_send_reply_start(request, evhttp_request_get_response_code(outgoingRequest), nullptr);
																									}
																									
																									// Reply with chunk to the request
																									evhttp_send_reply_chunk(request, evhttp_request_get_input_buffer(outgoingRequest));
																								}
																							}
																							
																							// Release outgoing request callback argument
																							outgoingRequestCallbackArgument.release();
																							
																							// Release request finished
																							requestFinished.release();
																						}));
																						
																						// Set outgoing request error callback
																						evhttp_request_set_error_cb(outgoingRequest.get(), ([](evhttp_request_error error, void *argument) {
																						
																							// Check if timeout occured
																							if(error == EVREQ_HTTP_TIMEOUT) {
																							
																								// Get outgoing request callback argument from argument
																								unique_ptr<tuple<evhttp_request *, const bool *, const string *, const uint16_t *, const bool *, evhttp_uri *, evhttp_connection *, bool *>> outgoingRequestCallbackArgument(reinterpret_cast<tuple<evhttp_request *, const bool *, const string *, const uint16_t *, const bool *, evhttp_uri *, evhttp_connection *, bool *> *>(argument));
																								
																								// Get request from outgoing request callback argument
																								evhttp_request *request = get<0>(*outgoingRequestCallbackArgument);
																								
																								// Get request finished from outgoing request callback argument
																								unique_ptr<bool> requestFinished(get<7>(*outgoingRequestCallbackArgument));
																								
																								// Remove all request headers
																								evhttp_clear_headers(evhttp_request_get_output_headers(request));
																							
																								// Reply with gateway timeout error to request
																								evhttp_send_reply(request, HTTP_GATEWAY_TIMEOUT, nullptr, nullptr);
																								
																								// Set that request is finished
																								*requestFinished = true;
																								
																								// Release outgoing request callback argument
																								outgoingRequestCallbackArgument.release();
																								
																								// Release request finished
																								requestFinished.release();
																							}
																							
																							// Otherwise check if cancel occured
																							else if(error == EVREQ_HTTP_REQUEST_CANCEL) {
																							
																								// Get outgoing request callback argument from argument
																								unique_ptr<tuple<evhttp_request *, const bool *, const string *, const uint16_t *, const bool *, evhttp_uri *, evhttp_connection *, bool *>> outgoingRequestCallbackArgument(reinterpret_cast<tuple<evhttp_request *, const bool *, const string *, const uint16_t *, const bool *, evhttp_uri *, evhttp_connection *, bool *> *>(argument));
																								
																								// Get request from outgoing request callback argument
																								evhttp_request *request = get<0>(*outgoingRequestCallbackArgument);
																								
																								// Get URI from outgoing request callback argument
																								unique_ptr<evhttp_uri, decltype(&evhttp_uri_free)> uri(get<5>(*outgoingRequestCallbackArgument), evhttp_uri_free);
																								
																								// Get SOCKS connection from outgoing request callback argument
																								unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)> socksConnection(get<6>(*outgoingRequestCallbackArgument), evhttp_connection_free);
																								
																								// Get request finished from outgoing request callback argument
																								unique_ptr<bool> requestFinished(get<7>(*outgoingRequestCallbackArgument));
																								
																								// Reply with bad gateway error to request
																								evhttp_send_reply(request, HTTP_BAD_GATEWAY, nullptr, nullptr);
																							}
																						}));
																						
																						// Check if setting outgoing request's host header failed
																						if(evhttp_add_header(evhttp_request_get_output_headers(outgoingRequest.get()), "Host", (evhttp_uri_get_host(uri.get()) + ((evhttp_uri_get_port(uri.get()) != NO_URI_PORT) ? ':' + to_string(evhttp_uri_get_port(uri.get())) : "")).c_str())) {
																						
																							// Reply with internal server error to request
																							evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																						}
																						
																						// Otherwise
																						else {
																					
																							// Check if request has headers
																							evkeyvalq *headers = evhttp_request_get_input_headers(request);
																							if(headers) {
																							
																								// Go through all of the request's headers
																								for(evkeyval *header = headers->tqh_first; header; header = header->next.tqe_next) {
																								
																									// Check if header isn't a host header
																									if(strcasecmp(header->key, "Host")) {
																									
																										// Check if header isn't chunked transfer encoding
																										if(strcasecmp(header->key, "Transfer-Encoding") || strcasecmp(header->value, "chunked")) {
																								
																											// Check if setting outgoing request's header to the header failed
																											if(evhttp_add_header(evhttp_request_get_output_headers(outgoingRequest.get()), header->key, header->value)) {
																											
																												// Reply with internal server error to request
																												evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																												
																												// Return
																												return;
																											}
																										}
																									}
																								}
																							}
																							
																							// Check if setting outgoing request's outgoing data to be the request's incomming data failed
																							if(evbuffer_add_buffer(evhttp_request_get_output_buffer(outgoingRequest.get()), evhttp_request_get_input_buffer(request))) {
																							
																								// Reply with internal server error to request
																								evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																							}
																							
																							// Otherwise
																							else {
																							
																								// Check if setting TLS connection's TLS request index failed
																								if(!SSL_set_ex_data(bufferevent_openssl_get_ssl(evhttp_connection_get_bufferevent(socksConnection.get())), tlsRequestIndex, outgoingRequest.get())) {
																								
																									// Reply with internal server error to request
																									evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																								}
																								
																								// Otherwise
																								else {
																								
																									// Check if not verifying
																									if(*noVerify) {
																									
																										// Set TLS connection to not verify peer
																										SSL_set_verify(bufferevent_openssl_get_ssl(evhttp_connection_get_bufferevent(socksConnection.get())), SSL_VERIFY_NONE, nullptr);
																									}
																									
																									// Otherwise
																									else {
																								
																										// Set TLS connection to verify peer
																										SSL_set_verify(bufferevent_openssl_get_ssl(evhttp_connection_get_bufferevent(socksConnection.get())), SSL_VERIFY_PEER, ([](int verifyResult, X509_STORE_CTX *certificateStoreContext) {
																										
																											// Check if getting TLS connection was successful
																											SSL *tlsConnection = reinterpret_cast<SSL *>(X509_STORE_CTX_get_ex_data(certificateStoreContext, SSL_get_ex_data_X509_STORE_CTX_idx()));
																											if(tlsConnection) {
																											
																												// Check if getting outgoing request was successful
																												evhttp_request *outgoingRequest = reinterpret_cast<evhttp_request *>(SSL_get_ex_data(tlsConnection, tlsRequestIndex));
																												if(outgoingRequest) {
																												
																													// Check if verify result failed
																													if(!verifyResult) {
																													
																														// Cancel outgoing request
																														evhttp_cancel_request(outgoingRequest);
																														
																														// Free outgoing request
																														evhttp_request_free(outgoingRequest);
																														
																														// Clear TLS connection's TLS request index
																														SSL_set_ex_data(tlsConnection, tlsRequestIndex, nullptr);
																													}
																												}
																												
																												// Otherwise
																												else {
																												
																													// Return failed result
																													return 0;
																												}
																											}
																											
																											// Return verify result
																											return verifyResult;
																										}));
																									}
																								
																									// Set path
																									const string path = ((evhttp_uri_get_path(uri.get()) && strlen(evhttp_uri_get_path(uri.get()))) ? evhttp_uri_get_path(uri.get()) : "/") + ((evhttp_uri_get_query(uri.get()) && strlen(evhttp_uri_get_query(uri.get()))) ? string("?") + evhttp_uri_get_query(uri.get()) : "") + ((evhttp_uri_get_fragment(uri.get()) && strlen(evhttp_uri_get_fragment(uri.get()))) ? string("#") + evhttp_uri_get_fragment(uri.get()) : "");
																									
																									// Check if making outgoing request failed
																									if(evhttp_make_request(socksConnection.get(), outgoingRequest.get(), evhttp_request_get_command(request), path.c_str())) {
																									
																										// Reply with internal server error to request
																										evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																									}
																									
																									// Otherwise
																									else {
																									
																										// Release URI
																										uri.release();
																										
																										// Release ownership of the SOCKS connection
																										evhttp_connection_free_on_completion(socksConnection.get());
																									
																										// Release SOCKS connection
																										socksConnection.release();
																										
																										// Take ownership of the outgoing request
																										evhttp_request_own(outgoingRequest.get());
																										
																										// Release outgoing request
																										outgoingRequest.release();
																										
																										// Release request finished
																										requestFinished.release();
																										
																										// Release outgoing request callback argument
																										outgoingRequestCallbackArgument.release();
																									}
																								}
																							}
																						}
																					}
																				}
																			}
																		}
																	}
																}
															}
														}
													}
													
													// Otherwise
													else {
													
														// Check if creating SOCKS connection failed
														unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)> socksConnection(evhttp_connection_base_bufferevent_new(bufferevent_get_base(socksBuffer.get()), nullptr, socksBuffer.get(), torAddress->c_str(), *torPort), evhttp_connection_free);
														if(!socksConnection) {
														
															// Reply with internal server error to request
															evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
														}
														
														// Otherwise
														else {
														
															// Release SOCKS buffer
															socksBuffer.release();
														
															// Set that SOCKS connection is connected
															socksConnection->state = EVCON_IDLE;
															
															// Check if creating request finished failed
															unique_ptr<bool> requestFinished = make_unique<bool>(false);
															if(!requestFinished) {
															
																// Reply with internal server error to request
																evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
															}
															
															// Otherwise
															else {
															
																// Check if creating outgoing request callback argument failed
																unique_ptr<tuple<evhttp_request *, const string *, const uint16_t *, const bool *, bool *>> outgoingRequestCallbackArgument = make_unique<tuple<evhttp_request *, const string *, const uint16_t *, const bool *, bool *>>(request, listenAddress, listenPort, usingTlsServer, requestFinished.get());
																if(!outgoingRequestCallbackArgument) {
																
																	// Reply with internal server error to request
																	evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																}
																
																// Otherwise
																else {
														
																	// Check if creating outgoing request failed
																	unique_ptr<evhttp_request, decltype(&evhttp_request_free)> outgoingRequest(evhttp_request_new(([](evhttp_request *outgoingRequest, void *argument) {
																	
																		// Get outgoing request callback argument from argument
																		unique_ptr<tuple<evhttp_request *, const string *, const uint16_t *, const bool *, bool *>> outgoingRequestCallbackArgument(reinterpret_cast<tuple<evhttp_request *, const string *, const uint16_t *, const bool *, bool *> *>(argument));
																		
																		// Get request from outgoing request callback argument
																		evhttp_request *request = get<0>(*outgoingRequestCallbackArgument);
																		
																		// Get listen address from outgoing request callback argument
																		const string *listenAddress = get<1>(*outgoingRequestCallbackArgument);
																		
																		// Get listen port from outgoing request callback argument
																		const uint16_t *listenPort = get<2>(*outgoingRequestCallbackArgument);
																		
																		// Get using TLS server from outgoing request callback argument
																		const bool *usingTlsServer = get<3>(*outgoingRequestCallbackArgument);
																		
																		// Get request finished from outgoing request callback argument
																		unique_ptr<bool> requestFinished(get<4>(*outgoingRequestCallbackArgument));
																		
																		// Check if outgoing request exists
																		if(outgoingRequest) {
																		
																			// Remove outgoing request error callback
																			evhttp_request_set_error_cb(outgoingRequest, nullptr);
																		
																			// Check if request isn't finished
																			if(!*requestFinished) {
																			
																				// Check if outgoing request was successful
																				if(evhttp_request_get_response_code(outgoingRequest)) {
																				
																					// Check if response to the request hasn't been started
																					if(!evhttp_request_get_response_code(request)) {
																					
																						// Initialize error occured
																						bool errorOccured = false;
																					
																						// Check if outgoing request has headers
																						evkeyvalq *headers = evhttp_request_get_input_headers(outgoingRequest);
																						if(headers) {
																						
																							// Go through all of the outgoing request's headers
																							for(evkeyval *header = headers->tqh_first; header; header = header->next.tqe_next) {
																							
																								// Check if header is a location or refresh header
																								if(!strcasecmp(header->key, "Location") || !strcasecmp(header->key, "Refresh")) {
																								
																									// Initialize value
																									string value;
																									
																									// Check if listen address is an IPv6 address
																									char temp[sizeof(in6_addr)];
																									if(inet_pton(AF_INET6, listenAddress->c_str(), temp) == 1) {
																									
																										// Set value
																										value = string(*usingTlsServer ? "https" : "http") + "://[" + *listenAddress + "]:" + to_string(*listenPort) + '/' + header->value;
																									}
																									
																									// Otherwise
																									else {
																								
																										// Set value
																										value = string(*usingTlsServer ? "https" : "http") + "://" + *listenAddress + ':' + to_string(*listenPort) + '/' + header->value;
																									}
																									
																									// Check if setting request's header to the header with the value failed
																									if(evhttp_add_header(evhttp_request_get_output_headers(request), header->key, value.c_str())) {
																									
																										// Set error occured
																										errorOccured = true;
																									
																										// Remove all request headers
																										evhttp_clear_headers(evhttp_request_get_output_headers(request));
																										
																										// Reply with internal server error to request
																										evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																									}
																								}
																								
																								// Otherwise
																								else {
																							
																									// Check if setting request's header to the header failed
																									if(evhttp_add_header(evhttp_request_get_output_headers(request), header->key, header->value)) {
																									
																										// Set error occured
																										errorOccured = true;
																									
																										// Remove all request headers
																										evhttp_clear_headers(evhttp_request_get_output_headers(request));
																										
																										// Reply with internal server error to request
																										evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																									}
																								}
																							}
																						}
																						
																						// Check if an error didn't occur
																						if(!errorOccured) {
																					
																							// Set request's outgoing data to be the outgoing request's incomming data
																							evbuffer_add_buffer(evhttp_request_get_output_buffer(request), evhttp_request_get_input_buffer(outgoingRequest));
																							
																							// Reply with respone to request
																							evhttp_send_reply(request, evhttp_request_get_response_code(outgoingRequest), nullptr, nullptr);
																						}
																					}
																					
																					// Otherwise
																					else {
																					
																						// Reply with chunk to the request
																						evhttp_send_reply_chunk(request, evhttp_request_get_input_buffer(outgoingRequest));
																						
																						// End reply with the request request
																						evhttp_send_reply_end(request);
																					}
																				}
																				
																				// Otherwise
																				else {
																				
																					// Remove all request headers
																					evhttp_clear_headers(evhttp_request_get_output_headers(request));
																				
																					// Reply with bad gateway error to request
																					evhttp_send_reply(request, HTTP_BAD_GATEWAY, nullptr, nullptr);
																				}
																			}
																			
																			// Cancel outgoing request
																			evhttp_cancel_request(outgoingRequest);
																			
																			// Free outgoing request
																			evhttp_request_free(outgoingRequest);
																		}
																		
																		// Otherwise check if request isn't finished
																		else if(!*requestFinished) {
																		
																			// Remove all request headers
																			evhttp_clear_headers(evhttp_request_get_output_headers(request));
																		
																			// Reply with bad gateway error to request
																			evhttp_send_reply(request, HTTP_BAD_GATEWAY, nullptr, nullptr);
																		}
																		
																	}), outgoingRequestCallbackArgument.get()), evhttp_request_free);
																	
																	if(!outgoingRequest) {
																	
																		// Reply with internal server error to request
																		evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																	}
																	
																	// Otherwise
																	else {
																	
																		// Outgoing request chunk callback
																		evhttp_request_set_chunked_cb(outgoingRequest.get(), ([](evhttp_request *outgoingRequest, void *argument) {
																		
																			// Get outgoing request callback argument from argument
																			unique_ptr<tuple<evhttp_request *, const string *, const uint16_t *, const bool *, bool *>> outgoingRequestCallbackArgument(reinterpret_cast<tuple<evhttp_request *, const string *, const uint16_t *, const bool *, bool *> *>(argument));
																			
																			// Get request from outgoing request callback argument
																			evhttp_request *request = get<0>(*outgoingRequestCallbackArgument);
																			
																			// Get listen address from outgoing request callback argument
																			const string *listenAddress = get<1>(*outgoingRequestCallbackArgument);
																			
																			// Get listen port from outgoing request callback argument
																			const uint16_t *listenPort = get<2>(*outgoingRequestCallbackArgument);
																			
																			// Get using TLS server from outgoing request callback argument
																			const bool *usingTlsServer = get<3>(*outgoingRequestCallbackArgument);
																			
																			// Get request finished from outgoing request callback argument
																			unique_ptr<bool> requestFinished(get<4>(*outgoingRequestCallbackArgument));
																			
																			// Check if request isn't finished
																			if(!*requestFinished) {
																		
																				// Check if outgoing request was successful
																				if(outgoingRequest && evhttp_request_get_response_code(outgoingRequest)) {
																				
																					// Check if response to the request hasn't been started
																					if(!evhttp_request_get_response_code(request)) {
																					
																						// Check if outgoing request has headers
																						evkeyvalq *headers = evhttp_request_get_input_headers(outgoingRequest);
																						if(headers) {
																						
																							// Go through all of the outgoing request's headers
																							for(evkeyval *header = headers->tqh_first; header; header = header->next.tqe_next) {
																							
																								// Check if header is a location or refresh header
																								if(!strcasecmp(header->key, "Location") || !strcasecmp(header->key, "Refresh")) {
																								
																									// Get value
																									const string value = string(*usingTlsServer ? "https" : "http") + "://" + *listenAddress + ':' + to_string(*listenPort) + '/' + header->value;
																									
																									// Check if setting request's header to the header with the value failed
																									if(evhttp_add_header(evhttp_request_get_output_headers(request), header->key, value.c_str())) {
																									
																										// Remove all request headers
																										evhttp_clear_headers(evhttp_request_get_output_headers(request));
																										
																										// Reply with internal server error to request
																										evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																										
																										// Set that request is finished
																										*requestFinished = true;
																										
																										// Release request finished
																										requestFinished.release();
																										
																										// Release outgoing request callback argument
																										outgoingRequestCallbackArgument.release();
																										
																										// Return
																										return;
																									}
																								}
																								
																								// Otherwise check if header isn't chunked transfer encoding
																								else if(strcasecmp(header->key, "Transfer-Encoding") || strcasecmp(header->value, "chunked")) {
																							
																									// Check if setting request's header to the header failed
																									if(evhttp_add_header(evhttp_request_get_output_headers(request), header->key, header->value)) {
																									
																										// Remove all request headers
																										evhttp_clear_headers(evhttp_request_get_output_headers(request));
																									
																										// Reply with internal server error to request
																										evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																										
																										// Set that request is finished
																										*requestFinished = true;
																										
																										// Release outgoing request callback argument
																										outgoingRequestCallbackArgument.release();
																										
																										// Release request finished
																										requestFinished.release();
																										
																										// Return
																										return;
																									}
																								}
																							}
																						}
																					
																						// Start reply to the request
																						evhttp_send_reply_start(request, evhttp_request_get_response_code(outgoingRequest), nullptr);
																					}
																					
																					// Reply with chunk to the request
																					evhttp_send_reply_chunk(request, evhttp_request_get_input_buffer(outgoingRequest));
																				}
																			}
																			
																			// Release outgoing request callback argument
																			outgoingRequestCallbackArgument.release();
																			
																			// Release request finished
																			requestFinished.release();
																		}));
																		
																		// Set outgoing request error callback
																		evhttp_request_set_error_cb(outgoingRequest.get(), ([](evhttp_request_error error, void *argument) {
																		
																			// Check if timeout occured
																			if(error == EVREQ_HTTP_TIMEOUT) {
																			
																				// Get outgoing request callback argument from argument
																				unique_ptr<tuple<evhttp_request *, const string *, const uint16_t *, const bool *, bool *>> outgoingRequestCallbackArgument(reinterpret_cast<tuple<evhttp_request *, const string *, const uint16_t *, const bool *, bool *> *>(argument));
																				
																				// Get request from outgoing request callback argument
																				evhttp_request *request = get<0>(*outgoingRequestCallbackArgument);
																				
																				// Get request finished from outgoing request callback argument
																				unique_ptr<bool> requestFinished(get<4>(*outgoingRequestCallbackArgument));
																				
																				// Remove all request headers
																				evhttp_clear_headers(evhttp_request_get_output_headers(request));
																			
																				// Reply with gateway timeout error to request
																				evhttp_send_reply(request, HTTP_GATEWAY_TIMEOUT, nullptr, nullptr);
																				
																				// Set that request is finished
																				*requestFinished = true;
																				
																				// Release outgoing request callback argument
																				outgoingRequestCallbackArgument.release();
																				
																				// Release request finished
																				requestFinished.release();
																			}
																		}));
																	
																		// Check if setting outgoing request's host header failed
																		if(evhttp_add_header(evhttp_request_get_output_headers(outgoingRequest.get()), "Host", (evhttp_uri_get_host(uri.get()) + ((evhttp_uri_get_port(uri.get()) != NO_URI_PORT) ? ':' + to_string(evhttp_uri_get_port(uri.get())) : "")).c_str())) {
																		
																			// Reply with internal server error to request
																			evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																		}
																		
																		// Otherwise
																		else {
																	
																			// Check if request has headers
																			evkeyvalq *headers = evhttp_request_get_input_headers(request);
																			if(headers) {
																			
																				// Go through all of the request's headers
																				for(evkeyval *header = headers->tqh_first; header; header = header->next.tqe_next) {
																				
																					// Check if header isn't a host header
																					if(strcasecmp(header->key, "Host")) {
																					
																						// Check if header isn't chunked transfer encoding
																						if(strcasecmp(header->key, "Transfer-Encoding") || strcasecmp(header->value, "chunked")) {
																				
																							// Check if setting outgoing request's header to the header failed
																							if(evhttp_add_header(evhttp_request_get_output_headers(outgoingRequest.get()), header->key, header->value)) {
																							
																								// Reply with internal server error to request
																								evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																								
																								// Return
																								return;
																							}
																						}
																					}
																				}
																			}
																			
																			// Check if setting outgoing request's outgoing data to be the request's incomming data failed
																			if(evbuffer_add_buffer(evhttp_request_get_output_buffer(outgoingRequest.get()), evhttp_request_get_input_buffer(request))) {
																			
																				// Reply with internal server error to request
																				evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																			}
																			
																			// Otherwise
																			else {
																			
																				// Set path
																				const string path = ((evhttp_uri_get_path(uri.get()) && strlen(evhttp_uri_get_path(uri.get()))) ? evhttp_uri_get_path(uri.get()) : "/") + ((evhttp_uri_get_query(uri.get()) && strlen(evhttp_uri_get_query(uri.get()))) ? string("?") + evhttp_uri_get_query(uri.get()) : "") + ((evhttp_uri_get_fragment(uri.get()) && strlen(evhttp_uri_get_fragment(uri.get()))) ? string("#") + evhttp_uri_get_fragment(uri.get()) : "");
																				
																				// Check if making outgoing request failed
																				if(evhttp_make_request(socksConnection.get(), outgoingRequest.get(), evhttp_request_get_command(request), path.c_str())) {
																				
																					// Reply with internal server error to request
																					evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																				}
																				
																				// Otherwise
																				else {
																				
																					// Release ownership of the SOCKS connection
																					evhttp_connection_free_on_completion(socksConnection.get());
																				
																					// Release SOCKS connection
																					socksConnection.release();
																					
																					// Take ownership of the outgoing request
																					evhttp_request_own(outgoingRequest.get());
																					
																					// Release outgoing request
																					outgoingRequest.release();
																					
																					// Release request finished
																					requestFinished.release();
																					
																					// Release outgoing request callback argument
																					outgoingRequestCallbackArgument.release();
																				}
																			}
																		}
																	}
																}
															}
														}
													}
												}
											
												// Break
												break;
										}
									}
								}
							
							}), nullptr, ([](bufferevent *buffer, short event, void *argument) {
							
								// Get SOCKS buffer from buffer
								unique_ptr<bufferevent, decltype(&bufferevent_free)> socksBuffer(buffer, bufferevent_free);
								
								// Get SOCKS buffer callbacks argument from argument
								unique_ptr<tuple<evhttp_request *, const bool *, const string *, const uint16_t *, const bool *, SSL_CTX *, const string *, const uint16_t *, evhttp_uri *, SocksState *>> socksBufferCallbacksArgument(reinterpret_cast<tuple<evhttp_request *, const bool *, const string *, const uint16_t *, const bool *, SSL_CTX *, const string *, const uint16_t *, evhttp_uri *, SocksState *> *>(argument));
								
								// Get request from SOCKS buffer callbacks argument
								evhttp_request *request = get<0>(*socksBufferCallbacksArgument);
								
								// Get URI from SOCKS buffer callbacks argument
								unique_ptr<evhttp_uri, decltype(&evhttp_uri_free)> uri(get<8>(*socksBufferCallbacksArgument), evhttp_uri_free);
								
								// Get SOCKS state from SOCKS buffer callbacks argument
								unique_ptr<SocksState> socksState(get<9>(*socksBufferCallbacksArgument));
								
								// Check if connected
								if(event & BEV_EVENT_CONNECTED) {
								
									// Check if enabling reading with the SOCKS buffer failed
									if(bufferevent_enable(socksBuffer.get(), EV_READ)) {
									
										// Remove SOCKS buffer callbacks
										bufferevent_setcb(socksBuffer.get(), nullptr, nullptr, nullptr, nullptr);
									
										// Reply with internal server error to request
										evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
									}
									
									// Otherwise
									else {
								
										// Set authentication request
										const uint8_t authenticationRequest[] = {
											0x05,
											0x01,
											0x00
										};
										
										// Check if sending authentication requests to the SOCKS proxy failed
										if(bufferevent_write(socksBuffer.get(), authenticationRequest, sizeof(authenticationRequest))) {
										
											// Remove SOCKS buffer callbacks
											bufferevent_setcb(socksBuffer.get(), nullptr, nullptr, nullptr, nullptr);
										
											// Reply with internal server error to request
											evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
										}
										
										else {
										
											// Release SOCKS buffer
											socksBuffer.release();
										
											// Release SOCKS buffer callbacks argument
											socksBufferCallbacksArgument.release();
										
											// Release URI
											uri.release();
										
											// Release SOCKS state
											socksState.release();
										}
									}
								}
								
								// Otherwise
								else {
								
									// Remove SOCKS buffer callbacks
									bufferevent_setcb(socksBuffer.get(), nullptr, nullptr, nullptr, nullptr);
								
									// Reply with internal server error to request
									evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
								}
							
							}), socksBufferCallbacksArgument.get());
							
							// Check if connecting to SOCKS proxy failed
							if(bufferevent_socket_connect_hostname(socksBuffer.get(), nullptr, AF_UNSPEC, torAddress->c_str(), *torPort)) {
							
								// Reply with internal server error to request
								evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
							}
							
							// Otherwise
							else {
							
								// Take ownership of the request
								evhttp_request_own(request);
								
								// Release URI
								uri.release();
								
								// Release SOCKS buffer
								socksBuffer.release();
							
								// Release SOCKS state
								socksState.release();
								
								// Release SOCKS buffer callbacks argument
								socksBufferCallbacksArgument.release();
							}
						}
					}
				}
			}
		}
		
	}), &httpServerRequestCallbackArgument);
	
	// Check if creating Tor configuration failed
	shared_ptr<tor_main_configuration_t> torConfiguration(tor_main_configuration_new(), tor_main_configuration_free);
	if(!torConfiguration) {
	
		// Display message
		cout << "Creating Tor configuration failed" << endl;
	
		// Return failure
		return EXIT_FAILURE;
	}
	
	// Check if getting Tor control socket failed
	tor_control_socket_t torControlSocket = tor_main_configuration_setup_control_socket(torConfiguration.get());
	if(torControlSocket == INVALID_TOR_CONTROL_SOCKET) {
	
		// Display message
		cout << "Getting Tor control socket failed" << endl;
	
		// Return failure
		return EXIT_FAILURE;
	}
	
	// Check if creating Tor connection from Tor control socket failed
	unique_ptr<bufferevent, decltype(&bufferevent_free)> torConnection(bufferevent_socket_new(eventBase.get(), torControlSocket, BEV_OPT_DEFER_CALLBACKS | BEV_OPT_THREADSAFE), bufferevent_free);
	if(!torConnection) {
	
		// Display message
		cout << "Creating Tor connection from Tor control socket failed" << endl;
	
		// Return failure
		return EXIT_FAILURE;
	}
	
	// Initialize Tor connected
	bool torConnected = false;
	
	// Initialize Tor connection callbacks argument
	tuple<const string *, const uint16_t *, const bool *, evhttp *, bool *, string *, uint16_t *> torConnectionCallbacksArgument(&listenAddress, &listenPort, &usingTlsServer, httpServer.get(), &torConnected, &torAddress, &torPort);
	
	// Set Tor connection callbacks
	bufferevent_setcb(torConnection.get(), ([](bufferevent *torConnection, void *argument) {
	
		// Get Tor connection callbacks argument from argument
		tuple<const string *, const uint16_t *, const bool *, evhttp *, bool *, string *, uint16_t *> *torConnectionCallbacksArgument = reinterpret_cast<tuple<const string *, const uint16_t *, const bool *, evhttp *, bool *, string *, uint16_t *> *>(argument);
		
		// Get listen address from Tor connection callbacks arguments
		const string *listenAddress = get<0>(*torConnectionCallbacksArgument);
		
		// Get listen port from Tor connection callbacks arguments
		const uint16_t *listenPort = get<1>(*torConnectionCallbacksArgument);
		
		// Get using TLS server from Tor connection callbacks arguments
		const bool *usingTlsServer = get<2>(*torConnectionCallbacksArgument);
		
		// Get HTTP server from Tor connection callbacks arguments
		evhttp *httpServer = get<3>(*torConnectionCallbacksArgument);
	
		// Get Tor connected from Tor connection callbacks argument
		bool *torConnected = get<4>(*torConnectionCallbacksArgument);
		
		// Get Tor address from Tor connection callbacks argument
		string *torAddress = get<5>(*torConnectionCallbacksArgument);
		
		// Get Tor port from Tor connection callbacks argument
		uint16_t *torPort = get<6>(*torConnectionCallbacksArgument);
		
		// Check if getting input from the Tor connection failed
		evbuffer *input = bufferevent_get_input(torConnection);
		if(!input) {
		
			// Display message
			cout << "Getting input from the Tor connection failed" << endl;
			
			// Remove Tor connection callbacks
			bufferevent_setcb(torConnection, nullptr, nullptr, nullptr, nullptr);
		
			// Exit failure
			quick_exit(EXIT_FAILURE);
		}
		
		// Otherwise
		else {
		
			// Get input's length
			const size_t length = evbuffer_get_length(input);
			
			// Check if getting data from input failed
			uint8_t data[length];
			if(evbuffer_copyout(input, data, length) == -1) {
			
				// Display message
				cout << "Getting data from input failed" << endl;
				
				// Remove data from input
				evbuffer_drain(input, length);
				
				// Remove Tor connection callbacks
				bufferevent_setcb(torConnection, nullptr, nullptr, nullptr, nullptr);
			
				// Exit failure
				quick_exit(EXIT_FAILURE);
			}
			
			// Otherwise check if removing data from input failed
			else if(evbuffer_drain(input, length)) {
			
				// Display message
				cout << "Removing data from input failed" << endl;
				
				// Remove Tor connection callbacks
				bufferevent_setcb(torConnection, nullptr, nullptr, nullptr, nullptr);
			
				// Exit failure
				quick_exit(EXIT_FAILURE);
			}
			
			// Otherwise
			else {
			
				// Check if Tor isn't connected
				if(!*torConnected) {
					
					// Check if Tor is connected
					const char connectedMessage[] = "250-status/circuit-established=1";
					
					if(length >= sizeof(connectedMessage) - sizeof('\0') && !memcmp(data, connectedMessage, sizeof(connectedMessage) - sizeof('\0'))) {
					
						// Set Tor connected
						*torConnected = true;
						
						// Display message
						cout << "Connected to the Tor network" << endl;
						
						// Check if getting SOCKS information from the Tor connection failed
						if(bufferevent_write(torConnection, "getinfo net/listeners/socks\n", sizeof("getinfo net/listeners/socks\n") - sizeof('\0'))) {
						
							// Display message
							cout << "Getting SOCKS information from the Tor connection failed" << endl;
							
							// Remove Tor connection callbacks
							bufferevent_setcb(torConnection, nullptr, nullptr, nullptr, nullptr);
						
							// Exit failure
							quick_exit(EXIT_FAILURE);
						}
					}
					
					// Otherwise
					else {
					
						// Check if creating timer event failed
						unique_ptr<event> timerEvent = make_unique<event>();
						if(!timerEvent) {
						
							// Display message
							cout << "Creating timer event failed" << endl;
							
							// Remove Tor connection callbacks
							bufferevent_setcb(torConnection, nullptr, nullptr, nullptr, nullptr);
						
							// Exit failure
							quick_exit(EXIT_FAILURE);
						}
						
						// Otherwise
						else {
						
							// Check if creating timer callback argument failed
							unique_ptr<tuple<bufferevent *, event *>> timerCallbackArgument = make_unique<tuple<bufferevent *, event *>>(torConnection, timerEvent.get());
							if(!timerCallbackArgument) {
							
								// Display message
								cout << "Creating timer callback argument failed" << endl;
								
								// Remove Tor connection callbacks
								bufferevent_setcb(torConnection, nullptr, nullptr, nullptr, nullptr);
							
								// Exit failure
								quick_exit(EXIT_FAILURE);
							}
							
							// Otherwise
							else {
							
								// Check if setting timer callback failed
								if(evtimer_assign(timerEvent.get(), bufferevent_get_base(torConnection), ([](evutil_socket_t signal, short events, void *argument) {
								
									// Get timer callback argument from argument
									unique_ptr<tuple<bufferevent *, event *>> timerCallbackArgument(reinterpret_cast<tuple<bufferevent *, event *> *>(argument));
									
									// Get Tor connection from timer callback argument
									bufferevent *torConnection = get<0>(*timerCallbackArgument);
									
									// Get timer event from timer callback argument
									unique_ptr<event> timerEvent(get<1>(*timerCallbackArgument));
									
									// Check if getting status from the Tor connection failed
									if(bufferevent_write(torConnection, "getinfo status/circuit-established\n", sizeof("getinfo status/circuit-established\n") - sizeof('\0'))) {
									
										// Display message
										cout << "Getting status from the Tor connection failed" << endl;
									
										// Remove Tor connection callbacks
										bufferevent_setcb(torConnection, nullptr, nullptr, nullptr, nullptr);
									
										// Exit failure
										quick_exit(EXIT_FAILURE);
									}
								
								}), timerCallbackArgument.get())) {
								
									// Display message
									cout << "Setting timer callback failed" << endl;
									
									// Remove Tor connection callbacks
									bufferevent_setcb(torConnection, nullptr, nullptr, nullptr, nullptr);
								
									// Exit failure
									quick_exit(EXIT_FAILURE);
								}
								
								// Otherwise
								else {
								
									// Set timer
									const timeval timer = {
									
										// Microseconds
										.tv_usec = CHECK_TOR_CONNECTED_INTERVAL_MICROSECONDS
									};
									
									// Check if adding timer event to the dispatched events failed
									if(evtimer_add(timerEvent.get(), &timer)) {
									
										// Display message
										cout << "Adding timer event to the dispatched events failed" << endl;
										
										// Remove Tor connection callbacks
										bufferevent_setcb(torConnection, nullptr, nullptr, nullptr, nullptr);
									
										// Exit failure
										quick_exit(EXIT_FAILURE);
									}
									
									// Otherwise
									else {
									
										// Release timer event
										timerEvent.release();
										
										// Release timer callback argument
										timerCallbackArgument.release();
									}
								}
							}
						}
					}
				}
				
				// Otherwise
				else {
				
					// Check if got SOCKS information
					const char socksInformationMessage[] = "250-net/listeners/socks=\"";
					
					if(length >= sizeof(socksInformationMessage) - sizeof('\0') && !memcmp(data, socksInformationMessage, sizeof(socksInformationMessage) - sizeof('\0'))) {
					
						// Check if getting SOCKS address delimiter failed
						const uint8_t *addressDelimiter = reinterpret_cast<uint8_t *>(memchr(&data[sizeof(socksInformationMessage) - sizeof('\0')], ':', length - (sizeof(socksInformationMessage) - sizeof('\0'))));
						if(!addressDelimiter) {
						
							// Display message
							cout << "Getting SOCKS address delimiter failed" << endl;
							
							// Remove Tor connection callbacks
							bufferevent_setcb(torConnection, nullptr, nullptr, nullptr, nullptr);
						
							// Exit failure
							quick_exit(EXIT_FAILURE);
						}
						
						// Otherwise
						else {
						
							// Get SOCKS address
							string socksAddress(reinterpret_cast<char *>(&data[sizeof(socksInformationMessage) - sizeof('\0')]), addressDelimiter - &data[sizeof(socksInformationMessage) - sizeof('\0')]);
							
							// Check if SOCKS address is invalid
							if(socksAddress.empty()) {
							
								// Display message
								cout << "SOCKS address is invalid" << endl;
								
								// Remove Tor connection callbacks
								bufferevent_setcb(torConnection, nullptr, nullptr, nullptr, nullptr);
							
								// Exit failure
								quick_exit(EXIT_FAILURE);
							}
							
							// Otherwise
							else {
							
								// Check if getting SOCKS port delimiter failed
								const uint8_t *portDelimiter = reinterpret_cast<uint8_t *>(memchr(&data[sizeof(socksInformationMessage) - sizeof('\0') + socksAddress.length() + sizeof(':')], '"', length - (sizeof(socksInformationMessage) - sizeof('\0') + socksAddress.length() + sizeof(':'))));
								if(!portDelimiter) {
								
									// Display message
									cout << "Getting SOCKS port delimiter failed" << endl;
									
									// Remove Tor connection callbacks
									bufferevent_setcb(torConnection, nullptr, nullptr, nullptr, nullptr);
								
									// Exit failure
									quick_exit(EXIT_FAILURE);
								}
								
								// Otherwise
								else {
								
									// Get SOCKS port
									string socksPort(reinterpret_cast<char *>(&data[sizeof(socksInformationMessage) - sizeof('\0') + socksAddress.length() + sizeof(':')]), portDelimiter - &data[sizeof(socksInformationMessage) - sizeof('\0') + socksAddress.length() + sizeof(':')]);
									
									// Check if SOCKS port is invalid
									if(socksPort.empty() || !all_of(socksPort.begin(), socksPort.end(), ::isdigit)) {
									
										// Display message
										cout << "SOCKS port is invalid" << endl;
										
										// Remove Tor connection callbacks
										bufferevent_setcb(torConnection, nullptr, nullptr, nullptr, nullptr);
									
										// Exit failure
										quick_exit(EXIT_FAILURE);
									}
									
									// Otherwise
									else {
									
										// Initialize port number
										int portNumber;
										
										// Initialize error occured
										bool errorOccured = false;
										
										// Try
										try {
										
											// Get port number from SOCKS port
											portNumber = stoi(socksPort);
										}
										
										// Catch errors
										catch(...) {
										
											// Display message
											cout << "SOCKS port is invalid" << endl;
											
											// Set error occured
											errorOccured = true;
											
											// Remove Tor connection callbacks
											bufferevent_setcb(torConnection, nullptr, nullptr, nullptr, nullptr);
										
											// Exit failure
											quick_exit(EXIT_FAILURE);
										}
										
										// Check if an error didn't occur
										if(!errorOccured) {
										
											// Check if port number is invalid
											if(portNumber < 1 || portNumber > UINT16_MAX) {
											
												// Display message
												cout << "SOCKS port is invalid" << endl;
												
												// Remove Tor connection callbacks
												bufferevent_setcb(torConnection, nullptr, nullptr, nullptr, nullptr);
											
												// Exit failure
												quick_exit(EXIT_FAILURE);
											}
											
											// Otherwise
											else {
											
												// Check if binding server to listen address and listen port failed
												if(evhttp_bind_socket(httpServer, listenAddress->c_str(), *listenPort)) {
												
													// Display message
													cout << "Binding server to " << *listenAddress << ':' << to_string(*listenPort) << " failed" << endl;
													
													// Remove Tor connection callbacks
													bufferevent_setcb(torConnection, nullptr, nullptr, nullptr, nullptr);
												
													// Exit failure
													quick_exit(EXIT_FAILURE);
												}
												
												// Otherwise
												else {
												
													// Set Tor address to SOCKS address
													*torAddress = socksAddress;
													
													// Set Tor port to port number
													*torPort = portNumber;
													
													// Set display port to if the listen port doesn't match the default server port
													const bool displayPort = (!*usingTlsServer && *listenPort != HTTP_PORT) || (*usingTlsServer && *listenPort != HTTPS_PORT);
											
													// Check if listen address is an IPv6 address
													char temp[sizeof(in6_addr)];
													if(inet_pton(AF_INET6, listenAddress->c_str(), temp) == 1) {
													
														// Display message
														cout << "Listening at " << (*usingTlsServer ? "https" : "http") << "://[" << *listenAddress << ']' << (displayPort ? ':' + to_string(*listenPort) : "") << endl;
													
														// Display message
														cout << "Example usage: " << (*usingTlsServer ? "https" : "http") << "://[" << *listenAddress << ']' << (displayPort ? ':' + to_string(*listenPort) : "") << "/https://check.torproject.org" << endl;
													}
													
													// Otherwise
													else {
													
														// Display message
														cout << "Listening at " << (*usingTlsServer ? "https" : "http") << "://" << *listenAddress << (displayPort ? ':' + to_string(*listenPort) : "") << endl;
													
														// Display message
														cout << "Example usage: " << (*usingTlsServer ? "https" : "http") << "://" << *listenAddress << (displayPort ? ':' + to_string(*listenPort) : "") << "/https://check.torproject.org" << endl;
													}
												}
											}
										}
									}
								}
							}
						}
					}
					
					// Otherwise
					else {
					
						// Display message
						cout << "Getting SOCKS information failed" << endl;
						
						// Remove Tor connection callbacks
						bufferevent_setcb(torConnection, nullptr, nullptr, nullptr, nullptr);
					
						// Exit failure
						quick_exit(EXIT_FAILURE);
					}
				}
			}
		}
		
	}), nullptr, nullptr, &torConnectionCallbacksArgument);
	
	// Check if enabling reading with the Tor buffer failed
	if(bufferevent_enable(torConnection.get(), EV_READ)) {
	
		// Display message
		cout << "Enabling reading with the Tor buffer failed" << endl;
	
		// Return failure
		return EXIT_FAILURE;
	}
	
	// Display message
	cout << "Connecting to the Tor network" << endl;
	
	// Check if sending authentication message to Tor connection failed
	if(bufferevent_write(torConnection.get(), "authenticate \"\"\n", sizeof("authenticate \"\"\n") - sizeof('\0'))) {
	
		// Display message
		cout << "sending authentication message to Tor connection failed" << endl;
	
		// Return failure
		return EXIT_FAILURE;
	}
	
	// Initialize generator
	random_device device;
	mt19937 generator(device());
	
	// Initialize distribution
	uniform_int_distribution<uint8_t> distribution(0, UINT8_MAX);
	
	// Loop until a unique temporary directory is created
	filesystem::path temporaryDirectory;
	while(true) {
	
		// Initialize random string
		stringstream randomString;
		
		// Go through all bytes in random string length
		for(size_t i = 0; i < TEMPORARY_DIRECTORY_LENGTH; ++i) {
		
			// Fill byte in random string
			randomString << hex << static_cast<uint16_t>(distribution(generator));
		}	
		
		// Set temporary directory
		temporaryDirectory = filesystem::temp_directory_path() / randomString.str();
		
		// Check if creating temporary directory was successful
		if(filesystem::create_directory(temporaryDirectory)) {
		
			// Break
			break;
		}
	}
	
	// Get temporary directory as a string
	const string &temporaryDirectoryString = temporaryDirectory.string();
	
	// Set Tor arguments
	const char *torArguments[] = {
	
		// Program name
		argv[0],
		
		// Quiet
		"--quiet",
		
		// Automatic SOCKS port
		"--SocksPort", "auto",
		
		// SOCKS policy to prevent non-localhost from connecting
		"--SocksPolicy", "accept 127.0.0.1, reject *",
		
		// Disable Geo IPv4
		"--GeoIPFile", "",
		
		// Disable Geo IPv6
		"--GeoIPv6File", "",
		
		// Disable configuration file
		"--torrc-file", "",
		
		// Ignore missing configuration file
		"--ignore-missing-torrc",
		
		// Data directory
		"--DataDirectory", temporaryDirectoryString.c_str(),
		
		// End
		nullptr
	};
	
	// Check if configuring Tor configuration with the Tor arguments failed
	if(tor_main_configuration_set_command_line(torConfiguration.get(), sizeof(torArguments) / sizeof(torArguments[0]) - 1, const_cast<char **>(torArguments))) {
	
		// Display message
		cout << "Configuring Tor configuration with the Tor arguments failed" << endl;
		
		// Remove temporary directory
		filesystem::remove_all(temporaryDirectory);
	
		// Return failure
		return EXIT_FAILURE;
	}
	
	// Initialize thread error
	atomic_bool threadError(false);
	
	// Create Tor thread
	thread torThread(([&eventBase, &torConfiguration, &temporaryDirectory, &threadError]() {
	
		// Check if Windows
		#ifdef _WIN32
		
			// Check if running Tor failed
			if(tor_run_main(torConfiguration.get()) != EXIT_SUCCESS) {
			
				// Display message
				cout << "Running Tor failed" << endl;
			
				// Set thread error
				threadError.store(true);
			}
		
		// Otherwise
		#else
	
			// Check if allowing all signals was successful
			sigset_t signalMask;
			if(!sigemptyset(&signalMask) && !pthread_sigmask(SIG_SETMASK, &signalMask, nullptr)) {
				
				// Check if running Tor failed
				if(tor_run_main(torConfiguration.get()) != EXIT_SUCCESS) {
				
					// Display message
					cout << "Running Tor failed" << endl;
					
					// Set thread error
					threadError.store(true);
				}
			}
			
			// Otherwise
			else {
			
				// Display message
				cout << "Allowing all signals failed" << endl;
			
				// Set thread error
				threadError.store(true);
			}
		#endif
		
		// Check if breaking out of event dispatch loop failed
		if(event_base_loopbreak(eventBase.get())) {
		
			// Display message
			cout << "Breaking out of event dispatch loop failed" << endl;
			
			// Remove temporary directory
			filesystem::remove_all(temporaryDirectory);
		
			// Exit failure
			quick_exit(EXIT_FAILURE);
		}
	}));
	
	// Check if running event dispatch loop failed
	if(event_base_dispatch(eventBase.get()) == -1) {
	
		// Display message
		cout << "Running event dispatch loop failed" << endl;
		
		// Remove temporary directory
		filesystem::remove_all(temporaryDirectory);
	
		// Exit failure
		quick_exit(EXIT_FAILURE);
	}
	
	// Otherwise
	else {
	
		// Initialize error occured
		bool errorOccured = false;
	
		// Check if Tor thread is joinable
		if(torThread.joinable()) {
		
			// Try
			try {
		
				// Join Tor thread
				torThread.join();
			}
			
			// Catch errors
			catch(...) {
			
				// Display message
				cout << "Joining Tor thread failed" << endl;
			
				// Set error occured
				errorOccured = true;
				
				// Remove temporary directory
				filesystem::remove_all(temporaryDirectory);
			
				// Exit failure
				quick_exit(EXIT_FAILURE);
			}
		}
		
		// Check if an error didn't occur
		if(!errorOccured) {
		
			// Check if a thread error occured
			if(threadError.load()) {
			
				// Remove temporary directory
				filesystem::remove_all(temporaryDirectory);
			
				// Return failure
				return EXIT_FAILURE;
			}
			
			// Check if removing temporary directory failed
			if(!filesystem::remove_all(temporaryDirectory)) {
			
				// Return failure
				return EXIT_FAILURE;
			}
			
			// Return success
			return EXIT_SUCCESS;
		}
	}
	
	// Return failure
	return EXIT_FAILURE;
}


// Supporting function implementation

// Check if Windows
#ifdef _WIN32

	// Add system certificate to certificate store
	bool addSystemCertificatesToCertificateStore(X509_STORE *certificateStore, const TCHAR *systemStoreName) {

		// Check if opening system store failed
		HCERTSTORE systemStore = CertOpenSystemStore(0, systemStoreName);
		if(!systemStore) {
		
			// Return false
			return false;
		}
		
		// Go through all certificates on the system store
		for(PCCERT_CONTEXT certificateContext = CertEnumCertificatesInStore(systemStore, nullptr); certificateContext; certificateContext = CertEnumCertificatesInStore(systemStore, certificateContext)) {
		
			// Check if decoding certificate failed
			unique_ptr<X509, decltype(&X509_free)> certificate(d2i_X509(nullptr, const_cast<const unsigned char **>(&certificateContext->pbCertEncoded), certificateContext->cbCertEncoded), X509_free);
			if(!certificate) {
			
				// Close system store
				CertCloseStore(systemStore, 0);
				
				// Return false
				return false;
			}
			
			// Check if adding certificate to the certificate store failed
			if(!X509_STORE_add_cert(certificateStore, certificate.get())) {
			
				// Close system store
				CertCloseStore(systemStore, 0);
				
				// Return false
				return false;
			}
		}
		
		// Check if closing system store failed
		if(!CertCloseStore(systemStore, 0)) {
		
			// Return false
			return false;
		}
		
		// Return true
		return true;
	}
#endif
