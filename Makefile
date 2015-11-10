
# The first target is the default if you just say "make".  In this
# case, "build" relies on "sample", because I want the executable to be
# called "sample"

all: addqueue showqueue rmqueue

# "sample" requires a set of object files
# $@ is a special variable: the target of the operation, in this case sample
# $? is the
addqueue: AddQueue.o
	gcc -g -o $@ AddQueue.o -lm
	
showqueue: ShowQueue.o
	gcc -g -o $@ ShowQueue.o -lm
	
rmqueue: RmQueue.o
	gcc -g -o $@ RmQueue.o -lm

# Before testing, we must compile.  
# Lines preceeded by @ aren't echoed before executing
# Execution will stop if a program has a non-zero return code;
# precede the line with a - to override that
test:	build
	./SecureFS "test1.txt"
	@echo "-----------"
	./SecureFS "test2.txt"
	@echo "-----------"

exec: build
	./SecureFS $(ARG)

clean:
	rm -f addqueue showqueue rmqueue *.core *.o
