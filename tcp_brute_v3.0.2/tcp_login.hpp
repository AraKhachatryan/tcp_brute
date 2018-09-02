/******************************************************************************
*  @file tcp_login.hpp
*  @brief tcp_login class defination, core autentification class
*  @version: 3.0.0
*  @author: Ara Khachatryan
*..............................................................................
*  @brief STATE_FLAGS is enum class with bitmask flags for tcp_login's state
*         used for setting tcp_state member
*..............................................................................
*  @param login_data is an autentification information (login and password)
*         for the target. type: std::vector<unsigned char>
*  @param tcp_debug_msg is an container for storing tcp_login's status messages
*  @return type: short int
*  @retval -1  when error occurred
*  @retval  0  when password not match
*  @retval  1  when password is found
*  @retval  2  when second reply from DVR not recognized
*..............................................................................
*  @brief Exact lenght of first reply message from DVR is 564
*         Exact length of the message to be sent to DVR is 116
*         Exact lenght of second reply message from DVR is 68 if login fail and
*               100 or 136 if login sucess, so define the max lenght 136
*..............................................................................
*  @brief tcp_debug() function for mesuare tcp_login's operational time and set
*         status message into tcp_debug_msg
******************************************************************************/

#ifndef TCP_LOGIN_HPP
#define TCP_LOGIN_HPP

#include <netinet/in.h> // for struct sockaddr_in

#include <chrono>
typedef std::chrono::time_point<std::chrono::high_resolution_clock> timer;

#include <vector>
typedef std::vector<unsigned char> char_vect;

#include <string>




enum STATE_FLAGS : unsigned char
{
	ERR_CORE    = 0x01,  // bit 0, core error
	
	ERR_SOCKET  = 0x02,  // bit 1, socket() eroor
	ERR_CONNECT = 0x04,  // bit 2, connect() eror
	
	ERR_RECV    = 0x08,  // bit 3, recv() error
	ERR_SEND    = 0x10,  // bit 4, send() error
	
	NOT_MATCH   = 0x20,  // bit 5, password not match
	PASS_FOUND  = 0x40,  // bit 6, password found
	NOT_RECOGN  = 0x80,  // bit 7, response not recognized
};


class tcp_login
{
private:
	unsigned char tcp_state;
	bool debugging;
	
	timer t1, t2;
	
	int socket_desc;
	struct sockaddr_in target;
	
	static short int recv_count;
	static short int send_count;
	
	char_vect tcp_reply;
	
	std::string tcp_debug_msg;
	
// private member functions
	void timer_start();
	void timer_end();
	void create_socket();  // throws pair< tcp_state, tcp_debug_msg >
	void connect_to();     // throws pair< tcp_state, tcp_debug_msg > 
	void tcp_debug();
	
public:
	// throws pair< tcp_state, tcp_debug_msg > undirectly
	tcp_login( const char * ip, short int port, bool debug_mode );
	
	~tcp_login();
	
	// throws pair< tcp_state, tcp_debug_msg >
	void receive_from( const size_t buff_size );
	// throws pair< tcp_state, tcp_debug_msg >
	void send_to( char_vect& login_data );
	
	// throws pair< tcp_state, tcp_debug_msg >
	void login_result( char_vect& tcp_failure_reply, 
					   char_vect& tcp_success_reply );
	
};

#endif // TCP_LOGIN_HPP
