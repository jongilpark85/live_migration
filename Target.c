#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	int i = 0;
	
	do
	{
		printf("%d ", i++);
		fflush(stdout); 
		
		// sleep() causes a crash on Ubuntu 17.10 (works fine on older versions)
		// Replace sleep() with a loop for now
		volatile int j = 0;
		while(j++ < 300000000){}

	} while (1);
	
	return 0;
}