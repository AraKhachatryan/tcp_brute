/******************************************************************************
*  @file search_hex_data.h
*  @brief function finds the first occurrence of the char array needle in the
*         char array haystack
*  @param haystack is the main C hex data array to be scanned 
*  @param length_h is the length of haystack array
*  @param needle is the small hex data array to be searched within haystack 
*  @param length_n is the length of needle array
*  @retval true if match
*  @retval false if not match 
*  @version 1.0.2
*  @author Ara Khachatryan 
******************************************************************************/

#ifndef SEARCH_HEX_DATA_H
#define SEARCH_HEX_DATA_H

#include <stdbool.h>

bool search_hex_data( unsigned char *haystack, size_t length_h, 
					unsigned char *needle, size_t length_n )
{
	int pos_h = 0;
	int pos_n = 0;
	
	for ( pos_h = 0; pos_h < length_h - length_n; pos_h++ ) {
		if ( haystack[pos_h] == needle[pos_n] ) {
			++pos_n;
			if ( pos_n == length_n) {
				return true;
			}
		} else {
			pos_h -= pos_n;
			pos_n = 0;
		}
	}
	
	return false;
}

#endif /* SEARCH_HEX_DATA_H */
