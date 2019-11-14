CC=gcc
CFLAGS=-I../lib/includes -Wall -Werror -Wextra -O3  -fPIE -fstack-protector-all -D_FORTIFY_SOURCE=2 -pedantic -pedantic-errors -pie -Wformat -Wformat-security 
#-Wconversion -Wstack-protector -Wsign-conversion
SOURCES= driver.c
LIBS=lib_aes.a

%.o: %.c 
	$(CC) -g -c -o $@ $< $(CFLAGS)

test_aes: $(SOURCES) 
	$(CC) -g -o $@ $^ $(CFLAGS) -L../lib/bin -laes

.PHONY: clean 

clean:
	rm -f test_aes 
	rm -f *.o   
