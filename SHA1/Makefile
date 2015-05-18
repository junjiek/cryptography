CROSS =
CXX   = $(CROSS)g++
RM    = rm -f
BIN_DIR = ./bin
$(shell mkdir -p ${BIN_DIR})

all: demo_sha1 test_sha1

demo_sha1: demo_sha1.cpp sha1.cpp sha1.hpp
	$(CXX) -std=c++11 -o $(BIN_DIR)/$@ demo_sha1.cpp sha1.cpp

test_sha1: test_sha1.cpp sha1.cpp sha1.hpp
	$(CXX) -std=c++11 -o $(BIN_DIR)/$@ test_sha1.cpp sha1.cpp

check: test_sha1
	$(BIN_DIR)/test_sha1

clean:
	$(RM) $(BIN_DIR)/demo_sha1 $(BIN_DIR)/test_sha1
