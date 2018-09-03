// tcp_login.cpp -- tcp_login class methots

#include "tcp_login.hpp"  // tcp_login class defination
#include "namespace_terminal.hpp" // namespace terminal

#include <sys/socket.h> // Core BSD socket functions and data structures
#include <arpa/inet.h>  // for manipulating IP addresses, for inet_addr()
#include <unistd.h>     // access to the POSIX operating system API, for close()
#include <fcntl.h>      // for for fcntl() - the non-blocking sockets

#include <iterator>
#include <algorithm>

#include <iomanip> // for setw()
#include <cstring> // for std::strerror(errno)
#include <sstream> // for std::ostringstream
#include <cerrno>  // for errno error codes in linux

#include <iostream>



short int tcp_login::recv_count = 0;
short int tcp_login::send_count = 0;


//////////////////////////////////////////////////////////////// public methods

tcp_login::tcp_login( const char * ip, short int port, bool debug_mode )
		  : tcp_state(0x00), debugging(debug_mode)
{

	timer_start();
	create_socket();

	// Change the socket into non-blocking state
	fcntl(socket_desc, F_SETFL, O_NONBLOCK);
	
	// Set remote target information
	target.sin_addr.s_addr = inet_addr( ip );
	target.sin_family = AF_INET;
	target.sin_port = htons( port );
	
	connect_to();
}


tcp_login::~tcp_login()
{
	close(socket_desc);
}


void tcp_login::receive_from( const size_t buff_size )
{
	tcp_reply.clear();
	tcp_reply.resize(buff_size, 0x00);
	
	if ( recv(socket_desc, tcp_reply.data(), tcp_reply.size(), MSG_WAITALL ) == -1 )
	{
		tcp_state |= (STATE_FLAGS::ERR_CORE | STATE_FLAGS::ERR_RECV);
		if ( debugging ) {
			tcp_debug();
		}
		throw std::make_pair( tcp_state, tcp_debug_msg );
	}
	++recv_count;
}


void tcp_login::send_to( char_vect& login_data )
{
	if ( send(socket_desc , login_data.data(), login_data.size(), MSG_CONFIRM ) == -1 )
	{
		tcp_state |= (STATE_FLAGS::ERR_CORE | STATE_FLAGS::ERR_SEND);
		if ( debugging ) {
			tcp_debug();
		}
		throw std::make_pair( tcp_state, tcp_debug_msg );
	}
	++send_count;
}


void tcp_login::login_result( char_vect& tcp_failure_reply,
							  char_vect& tcp_success_reply )
{
	
	if ( tcp_reply.end() !=
		std::search( tcp_reply.begin(), tcp_reply.end(),
		tcp_failure_reply.begin(), tcp_failure_reply.end() ) )
	{
	// password not match, no errors
		if ( debugging ) { tcp_debug(); }
		tcp_state |= STATE_FLAGS::NOT_MATCH;
		throw std::make_pair( tcp_state, tcp_debug_msg );
		
	} else if ( tcp_reply.end() !=
				std::search( tcp_reply.begin(), tcp_reply.end(),
				tcp_success_reply.begin(), tcp_success_reply.end() ) )
	{
	// Password Found!!!
		if ( debugging ) { tcp_debug(); }
		tcp_state |= STATE_FLAGS::PASS_FOUND;
		throw std::make_pair( tcp_state, tcp_debug_msg );
	} else {
	// dvr_reply_second not recognized
		if ( debugging ) { tcp_debug(); }
		tcp_state |= STATE_FLAGS::NOT_RECOGN;
		throw std::make_pair( tcp_state, tcp_debug_msg );
	}
	
}


/////////////////////////////////////////////////////////////// private methods

void tcp_login::timer_start()
{
	t1 = std::chrono::high_resolution_clock::now();
}


void tcp_login::timer_end()
{
	t2 = std::chrono::high_resolution_clock::now();
}


void tcp_login::create_socket()
{
	socket_desc = socket( AF_INET , SOCK_STREAM , IPPROTO_TCP );
	
	if ( socket_desc == -1 )
	{
		tcp_state |= (STATE_FLAGS::ERR_CORE | STATE_FLAGS::ERR_SOCKET);
		if ( debugging ) {
			tcp_debug();
		}
		throw std::make_pair( tcp_state, tcp_debug_msg );
	}
}


void tcp_login::connect_to()
{
	if ( connect(socket_desc, (struct sockaddr *)&target, sizeof(target)) == -1 )
	{
		tcp_state |= (STATE_FLAGS::ERR_CORE | STATE_FLAGS::ERR_CONNECT);
		if ( debugging ) {
			tcp_debug();
		}
		throw std::make_pair( tcp_state, tcp_debug_msg );
	}
}


void tcp_login::tcp_debug()
{
	std::ostringstream stringStream;
	
	// check if core tcp_login error occured
	if ( (tcp_state & STATE_FLAGS::ERR_CORE) == STATE_FLAGS::ERR_CORE )
	{
		stringStream << terminal::TEXT_BOLD << terminal::TEXTCOLOR_BLUE;
		
		// if core tcp_login error occured determine from which point
		// and put internal message into stream
		switch( (tcp_state &= ~STATE_FLAGS::ERR_CORE) )
		{
		case STATE_FLAGS::ERR_SOCKET :
			stringStream << "socket(): ";
			break;
		case STATE_FLAGS::ERR_CONNECT :
			stringStream << "connect(): ";
			break;
		case STATE_FLAGS::ERR_RECV :
			stringStream << terminal::RESET_ALL << terminal::TEXTCOLOR_BLUE 
						 << "No" << terminal::TEXT_BOLD 
						 << recv_count << " recv(): ";
			break;
		case STATE_FLAGS::ERR_SEND :
			stringStream << terminal::RESET_ALL << terminal::TEXTCOLOR_BLUE 
						 << "No" << terminal::TEXT_BOLD 
						 << send_count << " send(): ";
			break;
		}
		
		stringStream << terminal::RESET_ALL << terminal::TEXTCOLOR_RED;
		stringStream << strerror(errno);
		
	} else {
		
		stringStream << terminal::TEXT_BOLD << terminal::TEXTCOLOR_GREEN;
		
		// as tcp_login is normal operating
		switch( tcp_state )
		{
		case STATE_FLAGS::NOT_MATCH :
			stringStream << "password not match, no errors";
			break;
		case STATE_FLAGS::PASS_FOUND :
			stringStream << terminal::TEXTCOLOR_RED;
			stringStream << "Password Found!!!";
			break;
		case STATE_FLAGS::NOT_RECOGN :
			stringStream << terminal::TEXTCOLOR_BLUE;
			stringStream << "login response not recognized";
			break;
		}
	}
	
	timer_end();
	
	std::chrono::duration<double, std::milli> dt = t2 - t1;
	
	stringStream << terminal::Cursor_Horizontal_Absolute(70);
	stringStream << terminal::TEXT_BOLD << terminal::TEXTCOLOR_CYAN;
	
	if ( dt.count() < 1 )
	{
		stringStream << " " << std::setw(7) << std::setprecision(3)
					 << std::left << dt.count() << " ms";
	} else if ( dt.count() < 1000 )
	{
		stringStream << " " << std::setw(7) << std::setprecision(4)
					 << std::left << dt.count() << " ms";
	} else {
		stringStream << " " << std::setw(7) << std::setprecision(0) << std::fixed 
					 << std::left << dt.count() << " ms";
	}
	
	stringStream << terminal::RESET_ALL;
	
	tcp_debug_msg = stringStream.str();
}

