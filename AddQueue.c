#include<stdio.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<stdlib.h>
#include<string.h>
#include<stdbool.h>
#include<ctype.h>
#include<dirent.h>
#include<libgen.h>
#include<math.h>

#define QUEUE_DIR "/home/user01/queue/"

int getNextUniqueNumber() {
	DIR *dir;
	struct dirent *f;
	int lastNum = 0;
	
	if((dir = opendir(QUEUE_DIR)) != NULL) {
		while((f = readdir(dir)) != NULL) {
			printf("file: %s\n", f->d_name);
			char *token = strtok(f->d_name, "_");
			printf("token: %s\n", token);
			if(token == NULL) continue;
			int num = atoi(token);
			if(lastNum < num) lastNum = num;
		}
		closedir(dir);
	}
	return lastNum + 1;
}

char *copyFileToQueue(char *path, int number) {
	FILE *source = fopen(path, "r");
	if(source == NULL) {
		return "Could not access source file";
	}
	
	char *baseDest = basename(path);
	if(baseDest == NULL) {
		return "Could not get the base file name of source file";
	}
	
	char destPath[1024], strNum[8];
	int size = log10(number) + 2;
	strcpy(destPath, QUEUE_DIR);
	snprintf(strNum, size, "%d", number);
	strcat(destPath, strNum);
	strcat(destPath, "_");
	strcat(destPath, baseDest);

	FILE *dest = fopen(destPath, "w+");
	if(dest == NULL) {
		return "Could not create new file in spool queue directory";
	}
	
	
	char ch;
	while( (ch = fgetc(source)) != EOF) {
		fputc(ch, dest);
	}
	
	fclose(source);
	fclose(dest);
	
	return NULL;
}


int main(int argc, char *argv[]) {
    if(argc < 2) {
        printf("\nUSAGE:\n");
        printf("List of Files to add to queue\n");
        return 1;
    }
    
    int uniqueNumber = getNextUniqueNumber();
	if(uniqueNumber == 0) uniqueNumber++;
    
    int i = 1;
    for(;i<argc;i++) {
    	char *error = copyFileToQueue(argv[i], uniqueNumber++);
    	if(error == NULL) {
    		printf("%s: Y\n", argv[i]);
    	}else {
    		printf("%s: X %s\n", argv[i], error);
    	}
    }
    
    return 0;
}
