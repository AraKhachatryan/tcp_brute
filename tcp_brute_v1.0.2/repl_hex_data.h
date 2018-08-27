/******************************************************************************
*  @file repl_hex_data.h
*  @brief function for setting integer type password to the login hex data
*  @param hex_data is pointer to the login hex data with NULL password
*      @see hex_data.h
*  @param password is the current password that will be set to hex_data 
*  @brief digits_count() is function for returning password digits count
*  @version 1.0.1
*  @author Ara Khachatryan 
******************************************************************************/

#ifndef REPL_HEX_DATA_H
#define REPL_HEX_DATA_H


/* declaration of digits_count() function */
int digits_count(unsigned long int password);


void repl_hex_data(unsigned char *hex_data, unsigned long int password)
{
	int count = 0;
	count = digits_count(password);

	int i;
	for (i = count; i > 0; --i) {
		/**************************************************************
		* password digits are assigned to the hex_data as hexdecimal
		* represented chars from 58th byte
		* From ASCII table: 0x30 + digit (hexdecimal) <=> digit (char) 
		**************************************************************/
		hex_data[58+i-1] = 0x30 + password % 10;
		password /= 10;
	}
}


int digits_count(unsigned long int password)
{
	int count = 1;
	while ( password /= 10 ){
		++count;
	}
	return count;
}

#endif /* REPL_HEX_DATA_H */
