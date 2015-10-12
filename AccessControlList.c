#include<stdio.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<ftw.h>
#include<stdlib.h>
#include<string.h>
#include<stdbool.h>

#define MAX_FILE_NAME 256
#define MAX_COMPONENT_NAME 16
#define INIT_FILE_SIZE 5
#define INIT_ACL_SIZE 5

typedef struct userList {
    char **users;
    int numUsers;
    int userCapacity;
} userList;

typedef struct permission {
    char *user;
    char *group;
    bool read;
    bool write;
} permission;


typedef struct ACL {
    permission **permissions;
    int numPermissions;
    int permissionCapacity;
} ACL;


typedef struct file {
    char name[16];
    char path[256];
    struct file *parent;
    struct file **files;
    struct ACL *acl;
    int numFiles;
    int fileCapacity;
} file;


ACL *newPermission(ACL *acl, char *user, char *group, bool read, bool write) {
    permission *p = (permission *) malloc(sizeof(permission));
    p->user = (char *) malloc((strlen(user)+1) * sizeof(char));
    strncpy(p->user, user, strlen(user)+1);
    p->group = (char *) malloc((strlen(group)+1) * sizeof(char));
    strncpy(p->group, group, strlen(group)+1);
    p->read = read;
    p->write = write;
    
    if(acl->numPermissions == acl->permissionCapacity) {
        int capacity = acl->permissionCapacity * 2;
        permission **permissions = (permission **) malloc(capacity * sizeof(permission *));
        int i;
        for(i=0; i < acl->numPermissions; i++) {
            permissions[i] = acl->permissions[i];
        }
        permissions[i] = p;
        //free(acl->permissions);
        acl->permissions = permissions;
        acl->permissionCapacity = capacity;
        acl->numPermissions++;
    }else {
        acl->permissions[acl->numPermissions] = p;
        acl->numPermissions++;
    }
    return acl;
}


ACL *newACL(int permissionCapacity) {
    ACL *acl = (ACL *) malloc(sizeof(ACL));
    acl->permissions = (permission **) malloc(permissionCapacity * sizeof(permission *));
    acl->permissionCapacity = permissionCapacity;
    acl->numPermissions = 0;
    return acl;
}


file *newFile(const char *name, const char *path, file *parent,
                        ACL *acl, int fileCapacity) {
    
    //add more checks on string names!
    if(strlen(name) > 15) {
        printf("Error: directory name: %s is longer than 16 bytes\n", name);
        return NULL;
    }
    
    if(strlen(path) > 255) {
        printf("Error: directory path: %s is longer than 256 bytes\n", path);
        return NULL;
    }
    
    file *f = (file *) malloc(sizeof(file));
    strncpy(f->name, name, strlen(name) + 1);
    strncpy(f->path, path, strlen(path) + 1);
    f->parent = parent;
    f->numFiles = 0;
    f->fileCapacity = fileCapacity;
    
    if(parent != NULL) {
        if(addFile(parent, f) == -1) {
            free(f);
            printf("ERROR: Problem adding new file to file system\n");
            return NULL;
        }
    }
    
    f->files = (file **) malloc(fileCapacity * sizeof(file *));
    f->acl = acl;
    
    return f;
};

int addFile(file *parent, file *newFile) {
    int i;
    for(i=0; i < parent->numFiles; i++) {
        if(strcmp(parent->files[i]->name, newFile->name) == 0) {
            printf("Error: file with name: '%s' already exists\n", newFile->name);
            return -1;
        }
    }
    
    if(parent->numFiles == parent->fileCapacity) {
        int capacity = parent->fileCapacity * 2;
        file **newFiles = (file **) malloc(capacity * sizeof(file *));
        for(i=0; i < parent->numFiles; i++) {
            newFiles[i] = parent->files[i];
        }
        newFiles[i] = newFile;
        parent->fileCapacity = capacity;
        parent->files = newFiles;
        parent->numFiles++;
    }else {
        parent->files[parent->numFiles] = newFile;
        parent->numFiles++;
    }
    return 0;
}


int deleteACL(ACL *acl) {
    int i;
    for(i=0; i < acl->numPermissions; i++) {
        free(acl->permissions[i]->user);
        free(acl->permissions[i]->group);
        free(acl->permissions[i]);
    }
    
    free(acl->permissions);
    free(acl);
    return 0;
}


int deleteFile(file *f) {
    if(f->parent == NULL) {
        printf("ERROR: Can't delete a file in 'deleteFile' function with no parent\n");
        return -1;
    }
    
    char *name = f->parent->name;
    while(strcmp(name, f->name) != 0) {
        if(f->numFiles == 0) {
            free(f->files);
            deleteACL(f->acl);
            f->parent->numFiles--;
            f = f->parent;
            free(f->files[f->numFiles]);
        }else {
            f = f->files[f->numFiles-1];
        }
    }   
    return 0;
}

userList *addUser(userList *users, char *name) {
    if(users->numUsers == users->userCapacity) {
        int capacity = users->userCapacity * 2;
        char **newUsers = (char **) malloc(capacity * sizeof(char *));
        int i;
        for(i=0; i < users->numUsers; i++) {
            memcpy(newUsers[i], users->users[i], sizeof(users->users[i]));
            //newDirs[i] = parent->directories[i];
        }
        newUsers[i] = (char *) malloc((strlen(name)+1) * sizeof(char));
        strncpy(newUsers[i], name, strlen(name)+1);
        users->userCapacity = capacity;
        free(users->users);
        users->users = newUsers;
        users->numUsers++;
    }else {
        users->users[users->numUsers] = (char *) malloc((strlen(name)+1) * sizeof(char));
        strncpy(users->users[users->numUsers], name, strlen(name)+1);
        users->numUsers++;
    }
    return users;
}

int deleteFileSystem(file *root) {
    printf("deleting file system\n");
    deleteFile(root->files[1]);
    deleteFile(root->files[0]);
    
    free(root->files);
    deleteACL(root->acl);
    free(root);
    return 0;
}

bool checkForUser(userList *users, char *name) {
    int i;
    for(i=0; i < users->numUsers; i++) {
        if(strcmp(users->users[i], name) == 0) {
            return true;
        }
    }
    return false;
}

permission *getACLMatch(ACL *acl, char *user, char *group) {
    int i;
    for(i=0; i < acl->numPermissions; i++) {
        permission *p = acl->permissions[i];
        if(strcmp(p->user, user) == 0 || strcmp(p->user, "*") == 0) {
            if(strcmp(p->group, group) == 0) {
                return p;
            }else if(strcmp(p->group, "*") == 0) {
                return p;
            }
        }
    }
    return NULL;
}

bool changeFile(char *fileName, file **parent, char *user, char *group) {
    int i;
    file *parentFile = *parent;
    for(i=0; i < parentFile->numFiles; i++) {
        if(strcmp(parentFile->files[i]->name, fileName) == 0) {
            file *f = parentFile->files[i];
            permission *permission = getACLMatch(f->acl, user, group);
            if(permission == NULL) {
                return false;
            }
            
            if(!permission->read) {               
                return false;
            }
            *parent = f;
            return true;
        }
    }
    return false;
}

char *getUser(char *str) {
    char *token = strtok(str, ".");
    if(token == NULL) {
        return NULL;
    }else if(strlen(token) < 1) {
        return NULL;
    }

    return token;
}

char *getGroup() {
    char *token = strtok(NULL, ".");
    if(token == NULL) {
        return NULL;
    }
    return token;
}

file *getFile(char *user, char *group, char *path, file *root, 
                        char **fileName, char **error, char *status) {
    char *token = strtok(path, "/");
    char *token2;
    if(token == NULL) {
        char *tmp = "ERROR: Bad path";
        *error = (char *) malloc((strlen(tmp)+1) * sizeof(char));
        strncpy(*error, tmp, strlen(tmp)+1);
        *status = 'X';
        return NULL;
    }
    
    file *f = root;
    while(token != NULL) {
        if(!changeFile(token, &f, user, group)) {
            token2 = strtok(NULL, "/");
            if(token2 != NULL) {
                char *tmp = "ERROR: User does not have read permission on this path";
                *error = (char *) malloc((strlen(tmp)+1) * sizeof(char));
                strncpy(*error, tmp, strlen(tmp)+1);
                *status = 'N';
                return NULL;
            }
            if(fileName != NULL) {
                *fileName = (char *) malloc((strlen(token)+1) * sizeof(char));
                strncpy(*fileName, token, strlen(token)+1);
            }
            return f;
        }
        token = strtok(NULL, "/");
    }
    return f;
}

void printUserDefinition(int num, char status, char *error) {
    printf("%d\t%c\t%s\n", num, status, error);
}


file *handleUserDefinition(char *user, char *group, userList **users, file *prevFile,
                                char *filePath, file *root, int lineNum) { 
    if(checkForUser(*users, user)) {
        if(filePath != NULL) {
            printUserDefinition(lineNum, 'X', "ERROR: Second instance of a user can't have a file!");
            return prevFile;
        }
        
        if(prevFile == NULL) {
            printUserDefinition(lineNum, 'X', "ERROR: No file created for user\n");
            return prevFile;
        }
        
        prevFile->acl = newPermission(prevFile->acl, user, group, true, true);
        printf("Add perm to acl file: %s\n", prevFile->path);
        int i = 0;
        printf("permissions: \n");
        for(;i<prevFile->acl->numPermissions; i++) {
            permission *p = prevFile->acl->permissions[i];
            printf("perm%d: user: %s, group: %s, read: %d, write: %d\n", i, p->user, p->group, p->read, p->write);
        }
        
    }else {
        *users = addUser(*users, user);
        if(filePath == NULL) {
            printUserDefinition(lineNum, 'X', "ERROR: First instance of a user must have a file!");
            return prevFile;
        }
    
        if(filePath[strlen(filePath)-1] == '\n') {
            filePath[strlen(filePath)-1] = '\0';
        }
        
        char path[strlen(filePath)+1];
        strncpy(path, filePath, strlen(filePath)+1);
        
        char *fileName, *error, status;
        file *parent = getFile(user, group, filePath, root, &fileName, &error, &status);
        if(parent == NULL) {
            printUserDefinition(lineNum, 'X', error);
            free(error);
            return prevFile;
        }
 
        ACL *acl = newACL(INIT_ACL_SIZE);
        acl = newPermission(acl, user, group, true, true);
        prevFile = newFile(fileName, path, parent, acl, INIT_FILE_SIZE);
        free(fileName);
        if(prevFile == NULL) {
            printUserDefinition(lineNum, 'X', "ERROR: Could not create new file");
            deleteACL(acl);
            return prevFile;
        }        
    }
     
    printUserDefinition(lineNum, 'Y', "Success");
    return prevFile;
}

FILE *parseUserDefinition(FILE *fp, file *root, userList **users) {
    int bufSize = 1024, lineNum = 0;
    char *fileName, *error, status, line[bufSize];
    file *createdFile = NULL;
    
    while(fgets(line, bufSize, fp) != NULL) {
        printf("%s", line);
        char *token = strtok(line, " \n");
        lineNum++;
        char *user, *group, *token2;
        if(token == NULL) {
            if(strcmp(line, ".") == 0) {
                return fp;
            }else {
                printUserDefinition(lineNum, 'X', "ERROR: UnParseable line");
                continue;
            }
        }
        
        if(strcmp(token, ".") == 0) {
            return fp;
        }
        
        if(strcmp(token, "\n") == 0) {
            printUserDefinition(lineNum, 'X', "ERROR: Empty line");
            continue;
        }
        
        token2 = strtok(NULL, " ");
        
        if((user = getUser(token)) == NULL) {
            printUserDefinition(lineNum, 'X', "ERROR: Unparseable line");
            continue;
        }

        if((group = getGroup()) == NULL) {
            printUserDefinition(lineNum, 'X', "ERROR: Unparseable line");
            continue;
        }
        
        createdFile = handleUserDefinition(user, group, users, createdFile, token2, root, lineNum);
    }
    return fp;
}

    
ACL *handleAclEntry(ACL *acl, char *user, char *group, char *permissions) {
    int i = 0;
    bool read = false, write = false;
    for(i; i < strlen(permissions); i++) {
        if(permissions[i] == 'r') {
            read = true;
        }else if(permissions[i] == 'w') {
            write = true;
        }else if(permissions[i] == '-') {
            break;
        }else {
            deleteACL(acl);
            return acl;
        }
    }   
    return newPermission(acl, user, group, read, write);     
}

void skipACL(FILE *fp) {
    int bufSize = 1024;
    char line[bufSize];
    while(fgets(line, bufSize, fp) != NULL) {
        char *token = strtok(line, " \n");
        if(token == NULL) {
            continue;
        }
        
        if(strcmp(token, ".") == 0) {
            return;
        }
    }
}
     

ACL *parseACL(FILE *fp) {
    ACL *acl = newACL(INIT_ACL_SIZE);
    int bufSize = 1024;
    char line[bufSize];
    
    while(fgets(line, bufSize, fp) != NULL) {
        printf("%s", line);
        char *token = strtok(line, " \n");
        
        if(token == NULL) {
            deleteACL(acl);
            return NULL;
        }
        
        if(strcmp(token, ".") == 0) {
            return acl;
        }
        
        char identity[strlen(token)+1];
        strncpy(identity, token, strlen(token)+1);
        
        token = strtok(NULL, " ");
        if(token == NULL) {
            deleteACL(acl);
            return NULL;
        }
        
        if(token[strlen(token)-1] == '\n') {
            token[strlen(token)-1] = '\0';
        }
        
        char *user, *group;
        if((user = getUser(identity)) == NULL) {
            deleteACL(acl);
            return NULL;
        }

        if((group = getGroup()) == NULL) {
            deleteACL(acl);
            return NULL;
        }
        
        acl = handleAclEntry(acl, user, group, token);
    }
    return acl;
}
        

void printOperation(int num, char status, char *command, char *text) {
    printf("%d\t%c\t%s\t%s\n", num, status, command, text);
}

void handleRead(file *f, char *path, permission *p, int commandNum) {
    char *command = "READ";
    if(strcmp(f->path, path) != 0) {
        printOperation(commandNum, 'X', command, "ERROR: Could not find file on this path\n");
        return;
    }
    
    if(p->read){
        printOperation(commandNum, 'Y', command, "Read successful");
    }else {
        printOperation(commandNum, 'N', command, "This user does not have read permission for this path\n");
    }
}

void handleWrite(file *f, char *path, permission *p, int commandNum) {
    char *command = "WRITE";
    if(strcmp(f->path, path) != 0) {
        printOperation(commandNum, 'X', command, "ERROR: Could not find file on this path\n");
        return;
    }
    
    if(p->write) {
        printOperation(commandNum, 'Y', command, "Write Successful");
    }else {
        printOperation(commandNum, 'N', command, "This user does not have write permission for this path\n");
    }
}

void handleAcl(file *f, char *path, permission *p, int commandNum, FILE *fp) {
    char *command = "ACL";
    if(strcmp(f->path, path) != 0) {
        printOperation(commandNum, 'X', command, "ERROR: Could not find file on this path\n");
        skipACL(fp);
        return;
    }
    
    if(p->write) {
        ACL *acl = parseACL(fp);
        if(acl == NULL) {
            printOperation(commandNum, 'X', command, "ERROR: Unparseable ACL");
        }else {
            deleteACL(f->acl);
            f->acl = acl;
            printOperation(commandNum, 'Y', command, "Acl successful");
        }
    }else {
        printOperation(commandNum, 'N', command, "This user does not have write permission for this path\n");
        skipACL(fp);
    }
}

void handleCreate(file *f, char *path, char *fileName, permission *p, int commandNum, FILE *fp) {
    char *command = "CREATE";
    if(strcmp(f->path, path) == 0) {
        printOperation(commandNum, 'X', command, "ERROR: File already exists on this path\n");
        skipACL(fp);
        return;
    }
    
    if(p->write) {
        ACL *acl = parseACL(fp);
        if(acl == NULL) {
            printOperation(commandNum, 'X', command, "ERROR: Unparseable ACL");
        }else {
            f = newFile(fileName, path, f, acl, INIT_FILE_SIZE);
            if(f == NULL) {
                printOperation(commandNum, 'X', command, "ERROR: could not create file");
            }else {
                printOperation(commandNum, 'Y', command, "Create Successful");
            }
        }
    }else {
        printOperation(commandNum, 'N', command, "This user does not have write permission for this path\n");
        skipACL(fp);
    }
}

void handleDelete(file *f, char *path, permission *p, int commandNum, char *user, char *group) {
    char *command = "DELETE";
    if(strcmp(f->path, path) == 0) {
        if(f->numFiles > 0) {
            printOperation(commandNum, 'N', command, "Can't delete a file that is a parent to more files");
            return;
        }
        f = f->parent;
        if(f == NULL) {
            printOperation(commandNum, 'X', command, "ERROR: Could not find the file on this path");
            return;
        }else {
            p = getACLMatch(f->acl, user, group);
            if(p == NULL) {
                printOperation(commandNum, 'N', command, "User does not have write permission for this path");
                return;
            }
        }
    }else {
        printOperation(commandNum, 'X', command, "ERROR: File does not exist to delete");
        return;
    }
    
    if(p->write) {
        printOperation(commandNum, 'Y', command, "Delete successful");
    }else {
        printOperation(commandNum, 'N', command, "This user does not have write permission for this path");
    }
}

void handleOperation(char *user, char *group, file *root, char *path,
                            int commandNum, char *command, FILE *fp) {
    char *fileName = NULL;
    char *error = NULL;
    char status = NULL;
    char tempPath[strlen(path)+1];
    strncpy(tempPath, path, strlen(path)+1);
    file *f = getFile(user, group, tempPath, root, &fileName, &error, &status);
    if(f == NULL) {
        printOperation(commandNum, status, command, error);
        free(error);
        return;
    }
    free(error);
    
    
    permission *p = getACLMatch(f->acl, user, group);
    if(p == NULL) {
        printOperation(commandNum, 'X', command, "User does not have any permissions on this path");
        free(fileName);
        return;
    }
    
    if(strcmp(command, "READ") == 0) {
        handleRead(f, path, p, commandNum);
    }else if(strcmp(command, "WRITE") == 0) {
        handleWrite(f, path, p, commandNum);
    }else if(strcmp(command, "ACL") == 0) {
        handleAcl(f, path, p, commandNum, fp);
    }else if(strcmp(command, "CREATE") == 0) {
        handleCreate(f, path, fileName, p, commandNum, fp);
    }else if(strcmp(command, "DELETE") == 0) {
        handleDelete(f, path, p, commandNum, user, group);
    }else {
        printOperation(commandNum, 'X', command, "ERROR: Command not recognized");
    }

    if(fileName != NULL)
        free(fileName);                                     
}


FILE *parseOperations(FILE *fp, file *root) {
    int bufSize = 1024;
    char line[bufSize];
    int commandNum = 0;
    char *error;
    char status;
    
    while(fgets(line, bufSize, fp) != NULL) {
        printf("%s", line);
        error = NULL;
        file *f;    
        char *token = strtok(line, " \n");
        commandNum++;
        
        if(token == NULL) {
            printOperation(commandNum, 'X', NULL, "ERROR: UnParseable line");
            continue;
        }
        
        char command[strlen(token)+1];
        strncpy(command, token, strlen(token)+1);
        
        token = strtok(NULL, " ");
        if(token == NULL) {
            printOperation(commandNum, 'X', command, "ERROR: UnParseable line");
            continue;
        }
        
        char identity[strlen(token)+1];
        strncpy(identity, token, strlen(token)+1);
        
        token = strtok(NULL, " ");
        if(token == NULL) {
            printOperation(commandNum, 'X', command, "ERROR: UnParseable line");
            continue;
        }else if(strlen(token) == 0) {
            printOperation(commandNum, 'X', command, "ERROR: UnParseable line");
            continue;
        }
        
        if(token[strlen(token)-1] == '\n') {
            token[strlen(token)-1] = '\0';
        }
        char path[strlen(token)+1];
        strncpy(path, token, strlen(token)+1);
        printf("path: %s\n", path);
        
        char *user, *group;
        if((user = getUser(identity)) == NULL) {
            printOperation(commandNum, 'X', command, "ERROR: Unparseable line");
            continue;
        }

        if((group = getGroup()) == NULL) {
            printOperation(commandNum, 'X', command, "ERROR: Unparseable line");
            continue;
        }
        
        handleOperation(user, group, root, path, commandNum, command, fp);
    }
    return fp;
}
       


userList *parseInputFile(char *fileName, file *root) {
    FILE *fp;
    if((fp = fopen(fileName, "r")) == NULL) {
        printf("Error: Can't access input file: %s\n", fileName);
        return NULL;
    }
    
    userList *users = (userList *) malloc(sizeof(userList));
    users->numUsers = 0;
    users->userCapacity = 20;
    users->users = (char **) malloc(20 * sizeof(char *));
    fp = parseUserDefinition(fp, root, &users);
    fp = parseOperations(fp, root);
    
    fclose(fp);
    return users;
}



int main(int argc, char *argv[]) {
    if(argc < 2) {
        printf("\nUSAGE:\n");
        printf("Predefined tests: 'make test'\n");
        printf("User defined test: 'make exec ARG=<test file>'\n\n");
        return 1;
    }
    
    char *inputFile = argv[1];
    FILE *fp;
    if((fp = fopen(inputFile, "r")) == NULL) {
        printf("Error: Can't access input file: %s\n", inputFile);
        return 1;
    }
    fclose(fp);
   
    ACL *rootACL = newACL(1);
    if(rootACL == NULL) 
        return -1;
    rootACL = newPermission(rootACL, "*", "*", true, false);
    
    file *root = newFile("/", "/", NULL, rootACL, 2);
    if(root == NULL)
        return -1;

    ACL *homeACL = newACL(1);
    if(homeACL == NULL)
        return -1;
    homeACL = newPermission(homeACL, "*", "*", true, false);
    
    file *home = newFile("home", "/home", root, homeACL, INIT_FILE_SIZE);
    if(home == NULL)
        return -1;
   
    
    ACL *tmpACL = newACL(1);
    if(tmpACL == NULL) 
        return -1;
    tmpACL = newPermission(tmpACL, "*", "*", true, true);
    
    file *tmp = newFile("tmp", "/tmp", root, tmpACL, INIT_FILE_SIZE);
    if(tmp == NULL)
        return -1;
        
    userList *users = parseInputFile(inputFile, root);
    
    deleteFileSystem(root);
    int i;
    for(i=0; i < users->numUsers; i++) {
        free(users->users[i]);
    }
    free(users->users);
    free(users);
    
    return 0;
}
