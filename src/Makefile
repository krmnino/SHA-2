BD = $(realpath ../bin)
SD = $(realpath ../src)

SRC_FILES = sha256.c

OBJ_FILES = $(patsubst %.c,%.o, $(SRC_FILES))
OBJ_PATHS = $(addprefix $(BD)/,$(OBJ_FILES))

all: compile link

compile:
	gcc -c -g $(SD)/$(SRC_FILES)
	mv *.o $(BD)

link:
	gcc $(OBJ_PATHS) -o $(BD)/sha256

clean:
	rm $(BD)/*.o $(BD)/sha256