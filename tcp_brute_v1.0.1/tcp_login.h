/******************************************************************************
*  @file tcp_login.h
*  @brief Generic Network Brute-force
*  @version: 1.0.1
*  @author: Ara Khachatryan 
*
*  @param login_raw_data is an autentification information (login and password)
*         of specified target. Array length: 116, type: unsigned char
*  @return type: int
*  @retval -1  when error occurred
*  @retval  0  when password don't match
*  @retval  1  when password is found
******************************************************************************/

#ifndef TCP_LOGIN_H
#define TCP_LOGIN_H

#include <stdio.h> /* standard input/output library, for perror() */
#include <errno.h> /* for errno error codes in linux */ 
#include <stdlib.h> /* dynamic memory management, for calloc() */
#include <string.h> /* for strstr() function */
#include <stdbool.h> /* for supporting bool type */
#include <sys/socket.h> /* Core BSD socket functions and data structures */
#include <arpa/inet.h> /* for manipulating IP addresses, for inet_addr() */
#include <unistd.h> /* access to the POSIX operating system API, for close() */

/********************
* Internal parameters --->>
********************/

/* ip address and port number of target */
#define IP_ADDRESS "10.1.1.16"
#define PORT_NUMBER 3000

/******************************************************************************
* @brief Exact lenght of first reply message from target is 564
*        Exact length of the message to be sent to target is 116
*        Exact lenght of first reply message from target is 68
******************************************************************************/


int tcp_login ( unsigned char *login_raw_data )
{

	int socket_desc;
	struct sockaddr_in target;

	/* Create socket */
	socket_desc = socket( AF_INET , SOCK_STREAM , IPPROTO_TCP );
	if ( socket_desc == -1 ) {
		perror("Could not create socket");
		close(socket_desc);
		return -1;
	}
	
	/* Set remote target information */
	target.sin_addr.s_addr = inet_addr( IP_ADDRESS );
	target.sin_family = AF_INET;
	target.sin_port = htons( PORT_NUMBER );
	

	/****************************************************************************
	* Connect to remote target
	* If the connection or binding succeeds, 0 returned, otherwise -1
	****************************************************************************/
	if (connect(socket_desc, (struct sockaddr *)&target, sizeof(target)) == -1) {
		perror("dvr_login() -> connect() error");
//		printf( "tcp_login() -> connect() error: %s\n", strerror(errno) );
		close(socket_desc);
		return -1;
	}


	unsigned char *tcp_reply_first;
	tcp_reply_first = (unsigned char *)calloc(564, sizeof(unsigned char));
	unsigned char *tcp_reply_second;
	tcp_reply_second = (unsigned char *)calloc(68, sizeof(unsigned char));


	/****************************************************************************
	* Receive first reply from the target
	* recv() returns the length of the message on successful completion
	* Exact lenght of first reply message from target is 564
	* message contains information about the target 
	****************************************************************************/
	if ( recv(socket_desc, tcp_reply_first, 564 , MSG_WAITALL) == -1 ) {
		perror("first recv() failed");
//		printf( "first recv() failed: %s", strerror(errno) );
		free( tcp_reply_first ) ;
		free( tcp_reply_second );
		close(socket_desc);
		return -1;
	}

	/****************************************************************************
	* Send login_data to the target
	* send() on success return the number of bytes sent
	* Тhe exact length of the message to be sent is 116
	****************************************************************************/
	if ( send(socket_desc , login_raw_data , 116 , 0) == -1 ) {
		perror("login data send() failed");
//		printf( "login data send() failed: %s", strerror(errno) );
		free( tcp_reply_first ) ;
		free( tcp_reply_second );
		close(socket_desc);		
		return -1;
	}

	/****************************************************************************
	* Receive second reply from the target
	* recv() returns the length of the message on successful completion
	* Exact lenght of second reply message from target is 68
	****************************************************************************/
	if ( recv(socket_desc, tcp_reply_second, 68 , MSG_WAITALL) == -1 ) {
		perror("second recv() failed");
//		printf( "second recv() failed: %s", strerror(errno) );
		free( tcp_reply_first ) ;
		free( tcp_reply_second );
		close(socket_desc);
		return -1;
	}
	
	/****************************************************************************
	* If in second reply from target "COMMAND_LOGIN_FAIL" found, passsword not
	* match return 0, otherwize password found return 1
	* TODO: Optimize second reply classifying
	****************************************************************************/
	if ( strstr((const char*)tcp_reply_second, "COMMAND_LOGIN_FAIL") == NULL ) {
		free( tcp_reply_first ) ;
		free( tcp_reply_second );
		// dont close socket in this case for next step
		return 1;
	}

	printf("tcp_login() -> password not match, passed without errors\n");

	free( tcp_reply_first ) ;
	free( tcp_reply_second );
	close(socket_desc);

	return 0;
}

#endif /* TCP_LOGIN_H */
