CROSS =
RM    = rm -f
BIN_DIR = ./bin
$(shell mkdir -p ${BIN_DIR})

all:  test_sha3_512

test_sha3_512: test_sha3_512.c sha3_512.c sha3_512.h
	$(CC) -o $(BIN_DIR)/$@ test_sha3_512.c sha3_512.c

check: test_sha3_512
	$(BIN_DIR)/test_sha3_512

clean:
	$(RM) $(BIN_DIR)/demo_sha3_512 $(BIN_DIR)/test_sha3_512
