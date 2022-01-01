/******************************************************************************

                             Secure Programming
                                Experiment 1
                Format string attack and vulnerabilities

*******************************************************************************/

#include  <stdio.h> 
void main(int argc, char **argv)
{
	// This line is safe
	printf("%s\n", argv[1]);
 
	// This line is vulnerable
	printf(argv[1]);
}
