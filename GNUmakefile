# Common
prefix= /usr/local
libdir= $(prefix)/lib
incdir= $(prefix)/include
bindir= $(prefix)/bin

CC= clang

CFLAGS+= $(cflags)
CFLAGS+= -std=c99
CFLAGS+= -Wall -Wextra -Werror -Wsign-conversion
CFLAGS+= -Wno-unused-parameter -Wno-unused-function

LDFLAGS+= -lz
LDFLAGS+= $(ldflags)

PANDOC_OPTS= -s --toc --email-obfuscation=none

# Platform specific
platform= $(shell uname -s)

ifeq ($(platform), Linux)
	CFLAGS+= -DHTTP_PLATFORM_LINUX
	CFLAGS+= -D_POSIX_C_SOURCE=200809L
endif

# Debug
debug=0
ifeq ($(debug), 1)
	CFLAGS+= -g -ggdb
else
	CFLAGS+= -O2
endif

# Coverage
coverage?= 0
ifeq ($(coverage), 1)
	CC= gcc
	CFLAGS+= -fprofile-arcs -ftest-coverage
	LDFLAGS+= --coverage
endif

# Target: libhttp
libhttp_LIB= libhttp.a
libhttp_SRC= $(wildcard src/*.c)
libhttp_INC= $(wildcard src/*.h)
libhttp_PUBINC= src/http.h
libhttp_OBJ= $(subst .c,.o,$(libhttp_SRC))

$(libhttp_LIB): CFLAGS+=

# Target: tests
tests_SRC= $(wildcard tests/*.c)
tests_OBJ= $(subst .c,.o,$(tests_SRC))
tests_BIN= $(subst .o,,$(tests_OBJ))

$(tests_BIN): LDFLAGS+= -L.
$(tests_BIN): LDLIBS+= -lhttp -lio -lcore -lutest

# Target: examples
examples_SRC= $(wildcard examples/*.c)
examples_OBJ= $(subst .c,.o,$(examples_SRC))
examples_BIN= $(subst .o,,$(examples_OBJ))

$(examples_BIN): LDFLAGS+= -L.
$(examples_BIN): LDLIBS+= -lhttp -lio -lcore -lssl -lcrypto

# Target: doc
doc_SRC= $(wildcard doc/*.mkd)
doc_HTML= $(subst .mkd,.html,$(doc_SRC))

# Rules
all: lib tests examples doc

lib: $(libhttp_LIB)

tests: lib $(tests_BIN)

examples: lib $(examples_BIN)

doc: $(doc_HTML)

$(libhttp_LIB): $(libhttp_OBJ) $(libhttp_INC)
	$(AR) cr $@ $(libhttp_OBJ)

$(tests_OBJ): $(libhttp_LIB) $(libhttp_INC)
tests/%: tests/%.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(examples_OBJ): $(libhttp_LIB) $(libhttp_INC)
examples/%: examples/%.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.c: %.rl
	ragel -o $@ $<

doc/%.html: doc/*.mkd
	pandoc $(PANDOC_OPTS) -t html5 -o $@ $<

clean:
	$(RM) $(libhttp_LIB) $(wildcard src/*.o)
	$(RM) $(tests_BIN) $(wildcard tests/*.o)
	$(RM) $(examples_BIN) $(wildcard examples/*.o)
	$(RM) $(wildcard **/*.gc??)
	$(RM) -r coverage
	$(RM) -r $(doc_HTML)

coverage:
	lcov -o /tmp/libhttp.info -c -d . -b .
	genhtml -o coverage -t libhttp /tmp/libhttp.info
	rm /tmp/libhttp.info

install: lib
	mkdir -p $(libdir) $(incdir) $(bindir)
	install -m 644 $(libhttp_LIB) $(libdir)
	install -m 644 $(libhttp_PUBINC) $(incdir)

uninstall:
	$(RM) $(addprefix $(libdir)/,$(libhttp_LIB))
	$(RM) $(addprefix $(incdir)/,$(libhttp_PUBINC))

tags:
	ctags -o .tags -a $(wildcard src/*.[hc])

.PHONY: all lib tests doc clean coverage install uninstall tags
