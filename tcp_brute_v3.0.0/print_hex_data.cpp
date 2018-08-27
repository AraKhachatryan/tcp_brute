/******************************************************************************
*  @file print_hex_data.cpp
*  @brief print_hex_data() is function for displaying login data information.
*         Insted of NULL bytes are printed "."
*
*  @brief Login raw data with password: 1020  --->>
*         ..­Ã...admin.............................................1020.......
*         ...........................................NEND
*
*  @version 3.0.0
*  @author Ara Khachatryan
******************************************************************************/

#include <iostream>
#include "namespace_terminal.hpp"


void print_hex_data( unsigned char *hex_data, unsigned int data_length )
{
	std::ostringstream stringStream;
	
	stringStream << terminal::TEXT_BOLD << terminal::TEXTCOLOR_GREEN;
	
	// Print the login raw data array byte by byte
	for ( unsigned int i = 0; i < data_length; i++ ) {
		if ( hex_data[i] == 0x00 ) {
			// insted of NULL bytes print "."
			stringStream << ".";
		} else {
			stringStream << hex_data[i];
		}
	}
	
	stringStream << terminal::RESET_ALL << std::endl;
	
	std::string hex_data_string = stringStream.str();
	
	std::cout << hex_data_string << std::flush;
}

