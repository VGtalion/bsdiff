CFLAGS		+=	-O3 -Wall
LDFLAGS		+=	-lbz2
PREFIX		?=	/usr/local
INSTALL_PROGRAM	?=	${INSTALL} -c -s -m 555
INSTALL_MAN	?=	${INSTALL} -c -m 444

%:	%.c
	$(CC) $(CFLAGS) $? -o $@ $(LDFLAGS)

all:		bsdiff bspatch
bsdiff:		bsdiff.c
bspatch:	bspatch.c

install-bin:
	${INSTALL_PROGRAM} bsdiff bspatch ${PREFIX}/bin

install-man:
	${INSTALL_MAN} bsdiff.1 bspatch.1 ${PREFIX}/man/man1

install: install-bin install-man

clean:
	rm -f bsdiff bspatch

