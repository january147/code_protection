CC := gcc
OUT_DIR := ./out

all : boot test

boot : boot.c
	$(CC) boot.c -o $(OUT_DIR)/boot -lcrypto

test : test.c
	$(CC) test.c -o $(OUT_DIR)/test

encrypt : encrypt.c
	$(CC) encrypt.c -o $(OUT_DIR)/encrypt -lcrypto --debug

clean :
	rm $(OUT_DIR)/*