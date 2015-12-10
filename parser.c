/* parser.c
** Searches protocol of the packet that matches given checksum
** among all packets passed through nDPI
**
** Sokolov B.
*/

#include <stdio.h>
#include <stdlib.h>

#ifndef EINVAL
	#define EINVAL 22
#endif

#define CHKSM_SIZE 2
#define PRTCL_SIZE 4


typedef short int CHKSM_TYPE;
typedef int PRTCL_TYPE;

struct parser_str {
	CHKSM_TYPE checksum;
	PRTCL_TYPE protocol;
	char is_erased;
};

PRTCL_TYPE main (int argc, char *argv[])
{
	unsigned short int checksum_;
	
	if (argc != 2)
	{
		printf ("Parser: invalid arguement, expect to be 16-bit checksum");
		return(-EINVAL);
	}
	
	checksum_ = atoi(argv[1]);

	struct parser_str *memory_start;
/** TODO
	memory_start =
**/	
	int i = 0;

	for (i = 0;;i++)
	{	if (!(memory_start[i].is_erased))
			if (memory_start[i].checksum == checksum_) 
			{
				memory_start[i].is_erased = 1;			
				return memory_start[i].protocol;
			}
		else
			continue;
	}
}
