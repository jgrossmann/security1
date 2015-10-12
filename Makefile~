# A simple Makefile

# List the object files in one place
OBJ=AccessControlList.o

# The first target is the default if you just say "make".  In this
# case, "build" relies on "sample", because I want the executable to be
# called "sample"

build:	SecureFS

# "sample" requires a set of object files
# $@ is a special variable: the target of the operation, in this case sample
# $? is the
SecureFS: $(OBJ)
	gcc -g -o $@ $(OBJ)

# Before testing, we must compile.  
# Lines preceeded by @ aren't echoed before executing
# Execution will stop if a program has a non-zero return code;
# precede the line with a - to override that
test:	build
	./SecureFS "test1.txt"
	@echo "-----------"

exec: build
	./SecureFS $(ARG)

clean:
	rm -f sample *.core *.o
