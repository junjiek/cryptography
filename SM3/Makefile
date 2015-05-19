CROSS =
RM    = rm -f
BIN_DIR = ./bin
$(shell mkdir -p ${BIN_DIR})

all:  test_sm3

test_sm3: test_sm3.c sm3.c sm3.h
	$(CC) -o $(BIN_DIR)/$@ test_sm3.c sm3.c

check: test_sm3
	$(BIN_DIR)/test_sm3

clean:
	$(RM) $(BIN_DIR)/demo_sm3 $(BIN_DIR)/test_sm3
