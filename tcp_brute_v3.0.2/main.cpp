#include <iostream>

#include "tcp_brute.hpp"


int main()
{
	{
		tcp_brute brute(true, 5);
		brute.set_target_address( "10.1.1.16", 3000 );
		brute.set_password_range( 10000, 99999 );
		brute.create_threads();
	}
		
	return 0;
}
