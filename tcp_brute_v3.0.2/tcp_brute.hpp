#ifndef TCP_BRUTE_HPP
#define TCP_BRUTE_HPP

#include <thread>
#include <mutex>

#include <vector>
typedef std::vector<unsigned char> char_vect;

// create thread argument struct for bruteforce_thread()
typedef struct _thread_data_t
{
	int thread_id;
	unsigned long int pw_range_start;
	unsigned long int pw_range_end;
} thread_data_t;


class tcp_brute
{
private:
	bool debugging;
	short int num_threads;

	
	std::vector<std::thread> v_thread;
	std::vector<thread_data_t> t_data;
	
	std::mutex mutex_thread_iter;
	
	// thread attribute
	pthread_attr_t attr;
	
	unsigned long int passwd_range_start;
	unsigned long int passwd_range_end;
	
	const char * ip_address;
	short int port_number;
	
// private member functions
	void init_thread_args();
		
	void bruteforce_thread( const thread_data_t &t_data );

	
	void repl_hex_data( char_vect& hex_data, unsigned long int password );
	void print_hex_data( char_vect& );
	
	void thread_debug( std::string& FCN_msg, int threadID,
						unsigned long int passwd );
	
	
public:
	tcp_brute( bool debug_mode, short int threads_count ); 
	~tcp_brute();
	
	void set_password_range( unsigned long int start, unsigned long int end );
	void set_target_address( const char * ip, short int port );
	
	void create_threads();
	
//	print_hex_data();
	
};

#endif // TCP_BRUTE_HPP
