/******************************************************************************
*  @file print_hex_data
*  @brief print_hex_data() is function for displaying login data information.
*         Insted of NULL bytes are printed "."
*
*  @brief Login raw data with password: 1020  --->>
*         ..­Ã...admin.............................................1020.......
*         ...........................................NEND
*
*  @version 1.0.2
*  @author Ara Khachatryan
******************************************************************************/

#ifndef PRINT_HEX_DATA_H
#define PRINT_HEX_DATA_H

#include <stdio.h>
#include "search_hex_data.h" /* function for searching hex data in message */

void print_hex_data( unsigned char *hex_data, size_t data_length )
{
	int i;
	
	printf("\x1B[1;32m"); /* make terminal text bold and set green color */

	/* Print the login raw data array byte by byte */
	for ( i = 0; i < data_length; i++ ) {
		if ( hex_data[i] == 0x00 ) {
			/* insted of NULL bytes print "." */
			printf(".");
		} else {
			printf("%c", hex_data[i]);
		}
	}

	printf("\x1B[0m"); /* reset all text attributes via ASCII code */
	printf("\n");	
}

#endif /* PRINT_HEX_DATA_H */

