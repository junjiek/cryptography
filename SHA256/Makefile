CROSS =
RM    = rm -f
BIN_DIR = ./bin
$(shell mkdir -p ${BIN_DIR})

all:  test_sha256

test_sha256: test_sha256.c sha256.c sha256.h
	$(CC) -o $(BIN_DIR)/$@ test_sha256.c sha256.c

check: test_sha256
	$(BIN_DIR)/test_sha256

clean:
	$(RM) $(BIN_DIR)/demo_sha256 $(BIN_DIR)/test_sha256
