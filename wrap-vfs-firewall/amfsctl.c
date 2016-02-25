#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h> // for getopt
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "amfs_ioctl.h"
#include <linux/ioctl.h>


#define PAGE 4096

int read_file(char *dir);
int write_to_file(char *dir, char *str);

int main(int argc, char **argv){
	int ret = 0;
	int c;
	char *mp; // mount point
	int fd;
	struct user_pattern *ioctl_pat;
	int mode = 0;
	char arrays[32];
	char *passwd = arrays;

	opterr = 0;
	while ((c = getopt (argc, argv, "larh:")) != -1){
	    switch (c){
	      	case 'l': // list patterns
	      		// printf("%s\n", "display patterns");
	      		mode = 2;
	        	break;
	      	case 'a'://add patterns
	      		// printf("%s\n", "add patterns");
	      		mode = 0;
	        	break;
	      	case 'r'://remove pattern
	      		// printf("%s\n", "remove patterns");     
	      		mode = 1;
	        	break;
	      	case 'h'://helpful message
	        	printf("./amfsctl -l /mnt/amfs for listing patterns;\n");
	        	printf("./amfsctl -a <newpatt> /mnt/amfs for add the pattern;\n");
	        	printf("./amfsctl -r <oldpatt> /mnt/amfs for remove the pattern;\n");
	        	break;
	      	case '?':
		      	//no arg for -a -r	
		        if (optopt == 'a' || optopt == 'r'){
		          fprintf(stderr, "Error: Option -%c requires an argument.\n", optopt);
		        }
		        else if (isprint (optopt))
		          fprintf(stderr, "Error: Unknown option `-%c'.\n", optopt);
		        else
		          fprintf(stderr,
		                   "Error: Unknown option character `\\x%x'.\n",
		                   optopt);
	        	return 1;
	      	default:
	      		abort();
	    }//end switch
  	}//end while

  	printf("Password: \n");
  	scanf("%s", passwd);
  	// printf("now password is: %s\n", passwd);

  	mp = *(argv + argc - 1);
  	fd = open(mp, O_RDONLY);
	if(fd == -1){
		printf("Open mount point failed\n");
		ret = -EINVAL;
		goto out;
	}

	ret = ioctl(fd, IOCTL_PASSWD, passwd);
	if(ret >= 0){
		printf("%s\n", "Password matched!");
	}
	else {
		printf("%s\n", "Failed in passwd matching!");
		goto close_fd;
	}

	close(fd);

  	if(mode == 0 || mode  == 1){
  		mp = *(argv + argc - 1);
  		if(argc != 4){
			printf("Need argument!\n");
			ret =  -1;
			goto out;
  		}
  		fd = open(mp, O_RDONLY);
		if(fd == -1){
			printf("Open mount point failed\n");
			ret = -EINVAL;
			goto out;
		}
		ioctl_pat = malloc(sizeof(struct user_pattern));
		if(ioctl_pat == NULL){
			printf("%s\n", "Out of Memory.");
			ret = -ENOMEM;
			goto close_fd;
		}
		ioctl_pat->pat_len = strlen(argv[optind]);
		ioctl_pat->pat = argv[optind];
		if(mode == 0){
			ret = ioctl(fd, IOCTL_ADD, ioctl_pat);
			if(ret >= 0) printf("%s\n", "Succeed in adding");
			else{
				printf("%s\n", "Add Failed!");
				goto free_ioctl;
			}
		}
		if(mode == 1){
			ret = ioctl(fd, IOCTL_REMOVE, ioctl_pat);
			if(ret >= 0) printf("%s\n", "Succeed in removing");
			else{
				printf("%s\n", "Remove Failed!");
				goto free_ioctl;
			}
		}
  	}
  	if(mode == 2){
  		mp = *(argv + argc - 1);
  		fd = open(mp, O_RDONLY);
		if(fd == -1){
			printf("Open mount point failed\n");
			ret = -EINVAL;
			goto out;
		}
		int size;
		ret = ioctl(fd, IOCTL_SIZE, &size);
		int i;
		char *str;
		for(i = 0; i < size; i++){
			str = malloc(PAGE * sizeof(char));
			ret = ioctl(fd, IOCTL_LIST, str);
			if(ret >= 0){
				printf("%s\n", str);
			}
			else printf("%s\n", "Failed in listing");
			free(str);
		}
		goto close_fd;
  	}

	free_ioctl:
		free(ioctl_pat);
	close_fd:
		close(fd);
	out:
		exit(ret);

	//test
	// int ret = 0;
	// // char *dir = "test.txt";
	// // ret = read_file(dir);

	// // char *write_str = "ppppppp";
	// // ret = write_to_file(dir, write_str);


	// exit(ret);

}


int read_file(char *dir){
	FILE *file;
	char *line = malloc(PAGE);
	int ret = 0;

	file = fopen(dir, "r");
	if(file == NULL){
		printf("%s\n", "Fail to read test file!");
		ret = -EFAULT;
		return ret;
	}
	while(fgets(line, PAGE, file) != NULL){
		printf("%s", line);
	}
	// while (fscanf(file, "%s", line) != EOF) {
 //  		fprintf(file, "%s\n", line);
	// }
	fclose(file);
	// remove(dir);
	free(line);
	return ret;
}

int write_to_file(char *dir, char *str){
	int ret = 0;
	FILE *file;

	file = fopen(dir, "w");
	if(file == NULL){
		printf("%s\n", "Fail to write to test file!");
		ret = -EFAULT;
		return ret;
	}
	fprintf(file, "%s\n", str);
	fclose(file);

	return ret;

}
