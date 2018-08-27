/******************************************************************************
* @file loadBar.h
* @brief static inline loading bar on linux terminal --->>
*
* Current: 3312       ╠████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░╣  33%
*
* @version 1.0.1
* @author Ara Khachatryan
*..............................................................................
* @brief loadBar_fast(unsigned long int x, unsigned long int n, int r, int w)
*    @param x is initial number within (x...n) loop
*    @param n is final number within (x...n) loop
*    @param r is quantity of update time within (x...n) loop 
*    @param w is width of load bar
*..............................................................................
* @brief loadBar(unsigned long int x, unsigned long int n, int w)
*    @param x is initial number within (x...n) loop
*    @param n is final number within (x...n) loop
*    @param w is width of load bar
*..............................................................................
* @brief loadBar_fast() function operates faster than loadBar() because it 
*	 updates terminal only defined r time within (x...n) range and does
*	 less operations for printing tcp_login() function messages
* 
* @return type: static inline void
* 
* @brief draw_bar() function is the core drawing part of loadBar()
*..............................................................................
* @brief Used ANSI control codes and escape sequences, Ross's algorithm
*    @see http://en.wikipedia.org/wiki/ANSI_escape_code
*    @see http://ascii-table.com/ansi-escape-sequences.php
*    @see https://www.ross.click
******************************************************************************/

#ifndef LOADBAR_H
#define LOADBAR_H

#include <stdbool.h>
#include <stdio.h>

/* declaration of draw_bar() function */
inline void draw_bar( unsigned long int x, int completeness, int percent, int w );



/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/


static inline void loadBar_fast(unsigned long int x, unsigned long int n, int r, int w)
{	
	static bool first_time_flag = false; /* show bar on first time */
	
	/* IF completeness 100%, display load bar of 100% */
    if ( x == n ) {
		draw_bar( x, w, 100, w );
		return;
	/* update bar only r time within (x...n) range */
	} else if ( (x % ( n / r ) != 0) && first_time_flag ) {
		return;
	}
	first_time_flag = true;

	/**********************************************************************
	* Calculuate the ratio of complete-to-incomplete and the percent
	**********************************************************************/
	float ratio = (float)(x) / (float)(n);
	int completeness = ratio * w;
	int percent = (int)(ratio*100);
	
	draw_bar( x, completeness, percent, w );
	
	/* ANSI Control codes */
	/* to go back to the previous line and clear it. */
	printf("\x1B[F\x1B[J");	

}


/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/


static inline void loadBar(unsigned long int x, unsigned long int n, int w)
{
	
	static bool first_time_flag = true; /* first time in this function */

	/**********************************************************************
	* Calculuate the ratio of complete-to-incomplete and the percent
	**********************************************************************/
	float ratio = (float)(x) / (float)(n);
	int completeness = ratio * w;
	int percent = (int)(ratio*100);

	/* and if process is compete */
	if ( x == n ) {
		completeness = w;
		percent = 100;
	}

	if ( !first_time_flag ) {
		printf("\x1B[s");      /* save cursor current position */
	}

	if ( first_time_flag ) {
		printf("\x1B[2J");     /* clear the screen at the first time */
		printf("\x1B[0;0H");   /* move cursor to upper left position */
	}
	
	printf("\x1B[0;0H");       /* move cursor to upper left position */

	draw_bar( x, completeness, percent, w );

	if ( !first_time_flag ) {
		printf("\x1B[u");      /* restore cursor pervious position */
	}

	/**********************************************************************
	* If 24 row terminal screen is full, scroll full terminal page up and
	* draw the loading bar again so that it was looked static at first line 
	**********************************************************************/
	static unsigned long int call = 0; call++;
	if( call >= 23 ){
		printf("\x1B[1S");   /* scroll full terminal page up by 1 line */
		printf("\x1B[1F");   /* move cursor to beginning of 1 line up  */
		printf("\x1B[s");    /* save cursor current position */
		printf("\x1B[0;0H"); /* move cursor to upper left position */
		draw_bar( x, completeness, percent, w );
		printf("\x1B[u");    /* restore cursor pervious position */
	}

	/**********************************************************************
	* after loadBar print password label for tcp_login() output message -->
	* password 3312: connect() error: Network is unreachable
	**********************************************************************/
	printf("passwd ");
	printf("\x1B[1;33m");
	printf("%ld", x);
	printf("\x1B[0m");
	printf(": ");

	fflush(stdout); /* flush the buffer to the stdout stream immediately */

	first_time_flag = false; /* at now not first time in this function */

}



/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/


inline void draw_bar(unsigned long int x, int completeness, int percent, int w)
{

	int i = 0;
	
	printf("\x1B[1;32m"); /* make terminal text bold and set green color */
	
	/**********************************************************************
	* Show the current iteration on terminal --->> Current: 3312     ╠█████
	**********************************************************************/
	printf(" Current: %-10ld", x );
	printf("\x1B[1;36m");
	printf(" ╠"); /* or printf "\u2560" ( needs -std=c99 ) or "[" */
	printf("\x1B[1;32m");

	/**********************************************************************
	* Draw the loading bar --->> ╠███████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░╣
	**********************************************************************/
	for ( i = 0; i < completeness; i++ ) {
		printf("█"); /* or printf "\u2588" ( needs -std=c99 ) or "=" */
	}
 	for ( i = completeness; i < w; i++ ) {
		printf("░"); /* or printf "\u2591" ( needs -std=c99 ) or "." */
	}

	/**********************************************************************
	* Show the percentage of completeness on terminal --->> ░░░░░░░░░╣  33%
	**********************************************************************/
	printf("\x1B[1;36m");
	printf("╣ "); /* or printf "\u2563" ( needs -std=c99 ) or "]" */
	printf("\x1B[1;32m");
	printf("%3d%%", percent );

	printf("\x1B[0m"); /* reset all text attributes via ASCII code */

	printf("\n");

}


#endif /* LOADBAR_H */
