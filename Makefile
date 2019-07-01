# © 2018 Aaron Taylor <ataylor at subgeniuskitty dot com>
# See LICENSE.txt file for copyright and license details.

####################################################################################################
# Executables

CC              = cc

####################################################################################################
# Configuration

CC_FLAGS        = -fPIC -Wall -Wextra -ansi -pedantic -O2
NDD_SRC		!= ls *.c
INI_SRC		!= ls iniparser/*.c

####################################################################################################
# Targets

all: ndd

ndd:
	$(CC) $(CC_FLAGS) -o $@ $(NDD_SRC) $(INI_SRC)

clean:
	@rm -f ndd
