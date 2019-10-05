# © 2019 Aaron Taylor <ataylor at subgeniuskitty dot com>
# See LICENSE file for copyright and license details.

####################################################################################################
# Executables

CC          = cc

####################################################################################################
# Configuration

CC_FLAGS    = -Wall -pedantic -O2
SRC_FILES   = icmpmonitor.c iniparser/dictionary.c iniparser/iniparser.c

####################################################################################################
# Targets

all: icmpmonitor

icmpmonitor:
	$(CC) $(CC_FLAGS) -o $@ $(SRC_FILES)

clean:
	@rm -f icmpmonitor icmpmonitor.core

install: all
	@echo "Manually copy the 'icmpmonitor' binary where you please."
