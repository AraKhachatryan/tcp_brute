/******************************************************************************
*  @file tcp_login.cpp
*  @brief Generic Network Brute-force
*  @version: 3.0.0
*  @author: Ara Khachatryan
*..............................................................................
*  @param login_data is an autentification information (login and password)
*         of specified target. Array length: 116, type: unsigned char
*  @param FCN_msg is an container for storing tcp_login()'s status messages
*  @return type: short int
*  @retval -1  when error occurred
*  @retval  0  when password not match
*  @retval  1  when password is found
*  @retval  2  when second reply from target not recognized
*..............................................................................
*  @brief DEBUG_MODE, IP_ADDRESS, PORT_NUMBER are defined in tcp_brute.cpp file
*..............................................................................
*  @brief Exact lenght of first reply message from target is 564
*         Exact length of the message to be sent to target is 116
*         Exact lenght of second reply message from target is 68 if login fail 
*               and 100 or 136 if login sucess, so define the max lenght 136
*..............................................................................
*  @brief debug_FCN() function for mesuare tcp_login()'s operation time and set
*         status message into FCN_msg
******************************************************************************/

#include <iomanip> // for setw()
#include <cstring> // for std::strerror()
#include <sstream> // for std::ostringstream
#include <cerrno>  // for errno error codes in linux

#include <sys/time.h>   // defines the timeval structure, for gettimeofday()
#include <sys/socket.h> // Core BSD socket functions and data structures
#include <arpa/inet.h>  // for manipulating IP addresses, for inet_addr()

#include <unistd.h>    // access to the POSIX operating system API, for close()
#include <sys/fcntl.h> // for the non-blocking socket
#include <sys/select.h>


#include "namespace_terminal.hpp" // namespace terminal

extern unsigned char COMMAND_LOGIN_FAIL;
extern unsigned char admin;
extern bool DEBUG_MODE;
extern const char * IP_ADDRESS;
extern short int PORT_NUMBER;

extern bool search_hex_data( unsigned char *haystack, int length_h,
							unsigned char *needle, int length_n );

short int tcp_login( unsigned char* login_data, std::string& FCN_msg );

void debug_FCN( struct timeval t1, std::string& FCN_msg,
				const char* custom_msg );




short int tcp_login( unsigned char* login_data, std::string& FCN_msg )
{

	struct timeval t1;
	gettimeofday(&t1, NULL);
	
	int socket_desc;
	struct sockaddr_in target;
	
	// Create socket
	socket_desc = socket( AF_INET , SOCK_STREAM , IPPROTO_TCP );
	if ( socket_desc == -1 ) {
		close(socket_desc);
		if ( DEBUG_MODE ) {
			debug_FCN(t1, FCN_msg, "socket(): ");
		}
		return -1;
	}
	
	// Change the socket into non-blocking state
	//fcntl(socket_desc, F_SETFL, O_NONBLOCK);
	
	// Set remote target information
	target.sin_addr.s_addr = inet_addr( IP_ADDRESS );
	target.sin_family = AF_INET;
	target.sin_port = htons( PORT_NUMBER );
	
	
	/****************************************************************************
	* Connect to remote target
	* If the connection or binding succeeds, 0 returned, otherwise -1
	****************************************************************************/
	if (connect(socket_desc, (struct sockaddr *)&target, sizeof(target)) == -1) {
		close(socket_desc);
		if ( DEBUG_MODE ) {
			debug_FCN(t1, FCN_msg, "connect(): ");
		}
		return -1;
	}
	
	
	unsigned char *tcp_reply_first = nullptr;
	tcp_reply_first = new unsigned char [564]();
	unsigned char *tcp_reply_second = nullptr;
	tcp_reply_second = new unsigned char [136]();
	
	
	/****************************************************************************
	* Receive first reply from the target
	* recv() returns the length of the message on successful completion
	* Exact lenght of first reply message from target is 564
	* message contains information about the target 
	****************************************************************************/
	if ( recv(socket_desc, tcp_reply_first, 564 , MSG_WAITALL ) == -1 ) {
		delete []  tcp_reply_first;
		delete []  tcp_reply_second;
		close(socket_desc);
		if ( DEBUG_MODE ) {
			debug_FCN(t1, FCN_msg, "first recv(): ");
		}
		return -1;
	}
	
	/****************************************************************************
	* Send login_data to the target
	* send() on success return the number of bytes sent
	* Тhe exact length of the message to be sent is 116
	****************************************************************************/
	if ( send(socket_desc , login_data , 116 , MSG_CONFIRM ) == -1 ) {
		delete []  tcp_reply_first;
		delete []  tcp_reply_second;
		close(socket_desc);
		if ( DEBUG_MODE ) {
			debug_FCN(t1, FCN_msg, "send(): ");
		}
		return -1;
	}
	
	/****************************************************************************
	* Receive second reply from the target
	* recv() returns the length of the message on successful completion
	* Exact lenght of second reply message from target is 68
	****************************************************************************/
	int l = 0;
	if ( (l = recv(socket_desc, tcp_reply_second, 136, MSG_PEEK)) == -1 ) {
		delete []  tcp_reply_first;
		delete []  tcp_reply_second;
		close(socket_desc);
		if ( DEBUG_MODE ) {
			debug_FCN(t1, FCN_msg, "second recv(): ");
		}
		return -1;
	}
	
	/****************************************************************************
	* If in second reply from target "COMMAND_LOGIN_FAIL" found, passsword not
	* match return 0, otherwize password found return 1
	****************************************************************************/
	if ( search_hex_data(tcp_reply_second, l, &COMMAND_LOGIN_FAIL, 18) ) {
		delete []  tcp_reply_first;
		delete []  tcp_reply_second;
		close(socket_desc);
		if ( DEBUG_MODE ) {
			debug_FCN(t1, FCN_msg, "password not match, no errors");
		}
		return 0;
	// Password Found!!!
	} else  if ( search_hex_data(tcp_reply_second, l, &admin, 5) ) {
		delete []  tcp_reply_first;
		delete []  tcp_reply_second;
		if ( DEBUG_MODE ) {
			debug_FCN(t1, FCN_msg, "\x1B[1;31mPassword Found!!!");
		}
		// dont close socket in this case for next step
		return 1;
	// tcp_reply_second not recognized
	} else {
		delete []  tcp_reply_first;
		delete []  tcp_reply_second;
		if ( DEBUG_MODE ) {
			debug_FCN(t1, FCN_msg, "\x1B[1;34msecond reply not recognized");
		}
		return 2;
	}
	
}



void debug_FCN(struct timeval t1, std::string& FCN_msg, const char* custom_msg)
{
	std::ostringstream stringStream;
	
	if ( errno ) {
		stringStream << terminal::TEXT_BOLD << terminal::TEXTCOLOR_BLUE;
		stringStream << custom_msg;
		stringStream << terminal::TEXT_BOLD << terminal::TEXTCOLOR_RED;
		stringStream << strerror(errno);
	} else {
		stringStream << terminal::TEXT_BOLD << terminal::TEXTCOLOR_GREEN;
		stringStream << custom_msg;
	}
	
	struct timeval t2, t;
	
	gettimeofday(&t2, NULL);
	timersub(&t2, &t1, &t); // mesure time between t1 and t2 assign to t
	int dt = t.tv_sec*1000 + t.tv_usec/1000; // dt is elapsed time in ms
	
	stringStream << terminal::Cursor_Horizontal_Absolute(72);
	stringStream << terminal::TEXT_BOLD << terminal::TEXTCOLOR_CYAN;
	
	stringStream << " " << std::setw(4) << dt << " ms";
	stringStream << terminal::RESET_ALL;
	
	FCN_msg = stringStream.str();
}
