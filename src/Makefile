RD = $(realpath ../res)
BD = $(realpath ../bin)
SD = $(realpath ../src)

SRC_FILES = sha224.c    	\
            sha256.c    	\
            sha384.c    	\
            sha512.c		\
            sha512_224.c	\
            sha512_256.c
SRC_PATHS = $(addprefix $(SD)/,$(SRC_FILES))

OBJ_FILES = $(patsubst %.c,%.o, $(SRC_FILES))
OBJ_PATHS = $(addprefix $(BD)/,$(OBJ_FILES))

all:
	g++ -c -fPIC -Wall -std=c++17 $(SRC_PATHS) 
	mv *.o $(BD)
	g++ -shared -o $(RD)/libSHA2.so $(OBJ_PATHS)

clean:
	rm $(BD)/*.o $(RD)/*.o $(RD)/libSHA2.so