/******************************************************************************
*  @brief print_hex_data() is function for displaying login data information.
*         Insted of NULL bytes are printed "."
*
*  @brief Login raw data with password: 1020  --->>
*         ..­Ã...admin.............................................1020.......
*         ...........................................NEND
*
*  @version 1.0.1
*  @author Ara Khachatryan
******************************************************************************/

#ifndef PRINT_HEX_DATA_H
#define PRINT_HEX_DATA_H

#include <stdio.h>

void print_hex_data( unsigned char *login_data )
{
	int i;
	
	printf("\nLogin raw data with password: ");
	
	/* get the passwod within login data and print */
	for(i = 58; i < 75; i++) {
		if ( login_data[i] != 0x00 ) {
			printf("%c", login_data[i]);
		}
	}
	printf("  --->>\n");

	printf("\x1B[1;32m"); /* make terminal text bold and set green color */

	/* Print the login raw data array byte by byte */
	for(i = 0; i < 116; i++) {
		if ( login_data[i] == 0x00 ) {
			/* insted of NULL bytes print "." */
			printf(".");
		} else {
			printf("%c", login_data[i]);
		}
	}

	printf("\x1B[0m"); /* reset all text attributes via ASCII code */
	printf("\n\n");	
}

#endif /* PRINT_HEX_DATA_H */

