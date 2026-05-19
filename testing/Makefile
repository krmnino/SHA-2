BD = $(realpath ../bin)
RD = $(realpath ../res)
SD = $(realpath ../src)
TD = $(realpath ../testing)

SRC_FILES = sha224.c    	\
            sha256.c    	\
            sha384.c    	\
            sha512.c		\
            sha512_224.c	\
            sha512_256.c
SRC_PATHS = $(addprefix $(SD)/,$(SRC_FILES))
SRC_OBJ_FILES = $(patsubst %.c,%.o,$(SRC_FILES))
SRC_OBJ_PATHS = $(addprefix $(BD)/,$(SRC_OBJ_FILES))

TST_FILES = Main.c			\
			SHA2Testing.c	\
			Utils.c			\
			sha224_tc.c		\
			sha256_tc.c		\
			sha384_tc.c		\
			sha512_tc.c
TST_PATHS = $(addprefix $(TD)/,$(TST_FILES))			
TST_OBJ_FILES = $(patsubst %.c,%.o,$(TST_FILES))
TST_OBJ_PATHS = $(addprefix $(BD)/,$(TST_OBJ_FILES))

all: compile link

compile:
	gcc -Wall -c -g $(SRC_PATHS) $(TST_PATHS)
	mv *.o $(BD)

link:
	gcc $(SRC_OBJ_PATHS) $(TST_OBJ_PATHS) -L$(RD) -lRandomizer -lArgParsing -Wl,-rpath,$(RD)  -o $(BD)/sha2

example:
	gcc -c -g $(SRC_PATHS) SHA2Example.c
	mv *.o $(BD)
	gcc $(SRC_OBJ_PATHS) $(BD)/SHA2Example.o -o $(BD)/sha2_example

clean:
	rm $(BD)/*.o $(TD)/*.o $(BD)/sha2 $(BD)/sha2_example