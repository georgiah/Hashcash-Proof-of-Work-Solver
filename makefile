CC = gcc -std=gnu99 -m64

all: run_test_client clean server

test_crypto: sha256_test.c sha256.h
	$(CC) -g -o sha256_test sha256.c sha256_test.c

test_uint256: uint256_test.c uint256.h
	$(CC) -g -o uint256_test uint256_test.c

run_test_client: test_crypto test_uint256
	./sha256_test
	./uint256_test

server: server.c uint256.h sha256.h
	$(CC) -g -o server server.c sha256.c -pthread

run_server: server
	./server 36666

clean:
	rm -rf ./sha256_test ./uint256_test *.o

.PHONY = run_test_client clean
