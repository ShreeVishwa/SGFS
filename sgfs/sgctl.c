#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "sgctl.h"

int main(int argc, char* const argv[]){

	int ch, fd, err;
	while ((ch = getopt(argc, argv, "u")) != -1) {
		switch (ch) {
		case 'u':
			printf("The arg is %d\n",optind);
			fd = open(argv[optind], O_RDWR);
       			if(fd < 0) {
                		printf("Cannot open file...\n");
                		return 0;
        		}
			err = ioctl(fd, RD_VALUE, 0);
			close(fd);
			if(err == -1){
				printf("Reverting the file from the bin\n");
				return err;
			}
			return err;
			break;
		default:
			printf("Arguments insufficient\n");
			return 0;
			break;
		}
	}
	return 0;
}
