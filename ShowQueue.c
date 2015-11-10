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
#include<time.h>

#define QUEUE_DIR "/home/john/security/security2/" //"/home/user01/queue/"

typedef struct queueEntry {
	char name[512];
	uid_t owner;
	time_t time;
	char uniqueName[512];
	struct queueEntry *next;
	struct queueEntry *prev;
} queueEntry;

int getNumFiles() {
	DIR *dir;
	struct dirent *f;
	int numFiles = 0;
	
	if((dir = opendir(QUEUE_DIR)) != NULL) {
		while((f = readdir(dir)) != NULL) {
			if(strcmp(f->d_name, ".") == 0 || strcmp(f->d_name, "..") == 0) {
				continue;
			}
			numFiles++;
		}
		closedir(dir);
	}
	return numFiles;
}

void printList(queueEntry *root) {
	if(root == NULL) return;
	while(root != NULL) {
		struct tm *t = localtime(&(root->time));		
		printf("%s %d %d-%d-%d_%d:%d:%d\n", root->name, root->owner, (1900+t->tm_year), t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
		root = root->next;
	}
}

void deleteEntries(queueEntry *root) {
	if(root == NULL) return;
	while(root->next != NULL) {
		root = root->next;		
		free(root->prev);
	}
	free(root);
}

queueEntry *insert(queueEntry *root, queueEntry *newEntry) {
	if(root == NULL) {
		return newEntry;
	}else {
		queueEntry *curEntry = root;
		while(curEntry->next != NULL) {
			if(newEntry->time < curEntry->time) {
				if(curEntry->prev != NULL) {
					curEntry->prev->next = newEntry;
					newEntry->prev = curEntry->prev;
					curEntry->prev = newEntry;
					newEntry->next = curEntry;
					return root;
				}else {
					newEntry->next = curEntry;
					curEntry->prev = newEntry;
					return newEntry;
				}
			}
			curEntry = curEntry->next;
		}
		
		if(newEntry->time < curEntry->time) {
			if(curEntry->prev != NULL) {
				curEntry->prev->next = newEntry;
				newEntry->prev = curEntry->prev;
				curEntry->prev = newEntry;
				newEntry->next = curEntry;
				return root;
			}else {
				newEntry->next = curEntry;
				curEntry->prev = newEntry;
				return newEntry;
			}
		}else {
			curEntry->next = newEntry;
			newEntry->prev = curEntry;
		}
	}
	
	
	return root;
}

queueEntry *getFiles() {
	DIR *dir;
	struct dirent *f;
	int numFiles = getNumFiles();
	if(numFiles == 0) return NULL;
	queueEntry *root = NULL;
	
	if((dir = opendir(QUEUE_DIR)) != NULL) {
		while((f = readdir(dir)) != NULL) {
		
			if(strcmp(f->d_name, ".") == 0 || strcmp(f->d_name, "..") == 0) {
				continue;
			}
			queueEntry *entry = (queueEntry *) malloc(sizeof(queueEntry));
			entry->next = NULL;
			entry->prev = NULL;
			char name[128] = "";
			strncpy(name, f->d_name, strlen(f->d_name)+1);
			char *token = strtok(name, "_");
			strncpy(entry->name, f->d_name, strlen(f->d_name)+1);
			//strncpy(entry->name, token, strlen(token)+1);
			strncpy(entry->uniqueName, f->d_name+(strlen(token)+1), (strlen(f->d_name) - strlen(token)));
			
			char path[1024] = "";
			strncpy(path, QUEUE_DIR, strlen(QUEUE_DIR));
			strncat(path, f->d_name, strlen(f->d_name) + 1);
			
			struct stat statbuf;
			if(stat(path, &statbuf) == -1) {
				printf("Error getting file stats for file: %s\n", path);
				return NULL;
			}
			
			memcpy(&entry->owner, &statbuf.st_uid, sizeof(statbuf.st_uid));
			//entry->owner = statbuf.st_uid;
			entry->time = statbuf.st_mtime;
			
			root = insert(root, entry);
		}
		closedir(dir);
	}	
	 return root;
}


int main(int argc, char *argv[]) {
	
   	queueEntry *root = getFiles();
   	printList(root);
   	deleteEntries(root);	
    return 0;
}
