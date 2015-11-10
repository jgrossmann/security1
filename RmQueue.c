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

#define QUEUE_DIR "/home/john/security/security2/" //"/home/user01/queue/"


int checkOwnership(char *name, uid_t id) {
	char path[1024] = "";
	strncpy(path, QUEUE_DIR, strlen(QUEUE_DIR));
	strncat(path, name, strlen(name)+1);
	
	struct stat statbuf;
	if(stat(path, &statbuf) == -1) {
		return 0;
	}
	
	return statbuf.st_uid == id;
}

char *removeFromQueue(char *rmName, uid_t id) {
	DIR *dir;
	struct dirent *f;
	
	if((dir = opendir(QUEUE_DIR)) != NULL) {
		while((f = readdir(dir)) != NULL) {
			char name[128] = "", uniqueName[128];
			strncpy(name, f->d_name, strlen(f->d_name)+1);
			char *token = strtok(name, "_");
			strncpy(uniqueName, f->d_name, strlen(f->d_name)+1);
			//strncpy(entry->name, token, strlen(token)+1);
			//strncpy(entry->uniqueName, f->d_name+(strlen(token)+1), (strlen(f->d_name) - strlen(token)));
			if(strcmp(uniqueName, rmName) == 0) {
				if(checkOwnership(f->d_name, id)) {
					if(remove(f->d_name) == -1) {
						return "Could not remove file from spool queue directory";
					}else {
						return NULL;
					}
				}else {
					return "You Can't remove a file that you do not own";
				}
			}
		}
		closedir(dir);
	}	
	return "File does not exist in queue";
}

int main(int argc, char *argv[]) {
	if(argc < 2) {
        printf("\nUSAGE:\n");
        printf("List of Files to remove from queue\n");
        return 1;
    }
	
	uid_t id = getuid();
	
  	int i = 1;
    for(;i<argc;i++) {
    	char *error = removeFromQueue(argv[i], id);
    	if(error == NULL) {
    		printf("%s: Y\n", argv[i]);
    	}else {
    		printf("%s: X %s\n", argv[i], error);
    	}
    }
    
    return 0;
}
