CC=gcc
CFLAGS=-I./includes -Wall -Werror -Wextra -O3  -fPIE -fstack-protector-all -D_FORTIFY_SOURCE=2 -pedantic -pedantic-errors -pie -Wformat -Wformat-security 
#-Wconversion -Wstack-protector -Wsign-conversion
HEADERS = aes.h inv_aes.h decrypt.h encrypt.h utils.h padding.h
SOURCES = aes.o inv_aes.o encrypt.o decrypt.o utils.o padding.o

SOURCES_DIR=$(addprefix src/, $(SOURCES))
HEADERS_DIR=$(addprefix includes/, $(HEADERS))

src/%.o: %.c $(HEADERS)
	$(CC) -g -c -o $@ $< $(CFLAGS)

bin/libaes.a: $(SOURCES_DIR) 
	ar rcs $@ $^

.PHONY: clean 

clean:
	rm -f bin/libaes.a 
	rm -f src/*.o   
