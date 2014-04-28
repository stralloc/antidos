GCC=/src/dietlibc/bin-i386/diet gcc
#GCC=gcc
CFLAGS=-Wall -Os -I/src/libowfat -nostdinc
LDDFLAGS=-L/src/libowfat -lowfat -static -nostdinc
BIN_ANTIDOS=antidos
STRIP_ARGS=-R .note -R .comment -R .gnu.version
INDENT=indent -linux -l256 -lc256

all:
	${GCC} ${CFLAGS} -c antidos.c
	strip -x ${STRIP_ARGS} antidos.o
	${GCC} ${CFLAGS} antidos.o -o ${BIN_ANTIDOS} ${LDDFLAGS}
	strip -s ${STRIP_ARGS} ${BIN_ANTIDOS}

indent:
	${INDENT} antidos.c

clean:
	rm -f *.o ${BIN_ANTIDOS}
