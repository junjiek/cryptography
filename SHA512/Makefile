CROSS =
RM    = rm -f
BIN_DIR = ./bin
$(shell mkdir -p ${BIN_DIR})

all:  test_sha512

test_sha512: test_sha512.c sha512.c sha512.h
	$(CC) -o $(BIN_DIR)/$@ test_sha512.c sha512.c

check: test_sha512
	$(BIN_DIR)/test_sha512

clean:
	$(RM) $(BIN_DIR)/demo_sha512 $(BIN_DIR)/test_sha512
