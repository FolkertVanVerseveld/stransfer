#!/bin/bash -e
# Simple script that creates a Makefile for all c files that contain a main function
DEP=${DEP:-no}
CC=gcc
cstd='-std=gnu99'
CFLAGS="-D_LARGEFILE64_SOURCE -Wall -Wextra -pedantic $cstd $*"
INCS=
cat <<END >.gitignore
# Created by build script. Modifications are lost when rerun.
.gitignore
Makefile
*.tmp
# VIM
*.swp
*.vim
# CC
*.o
END
CFLAGS="$CFLAGS $INCS"
libs='ncurses'
if ! hash pkg-config 2>/dev/null; then
	echo "pkg-config is missing" 1>&2
	exit 1
fi
CFLAGS="$CFLAGS $(pkg-config --cflags $libs)"
LDLIBS="$(pkg-config --libs $libs)"
# Write phony target and overwrite some builtin variables
cat <<END >Makefile
.PHONY: default clean

CC?=$CC
CFLAGS=$CFLAGS
LDLIBS=$LDLIBS

END

printf "MAIN=" >>Makefile
# Filter Binary.* and strip extensions
MAIN=$(grep -r 'int main' | sed -e '/Binary.*/d' -e 's/:.*//g')
# Write elf executables
for i in $MAIN; do
	bin="${i/%.c/}"
	echo "$bin" >>.gitignore
	printf ' \\\n\t%s' "$bin" >>Makefile
done
# Write object files
printf '\nOBJECTS=' >>Makefile
FILES=$(find . -name '*.c')
FILES="${FILES//.\//}"
for i in $FILES; do
	printf ' \\\n\t%s' "${i/%.c/.o}" >>Makefile
done
for i in $MAIN; do
	FILES="${FILES/$i/}"
done
printf '\nLIST=' >>Makefile
for i in $FILES; do
	printf ' \\\n\t%s' "${i/%.c/.o}" >>Makefile
done
cat <<'EOF' >>Makefile

default: $(OBJECTS) $(MAIN)
EOF
for i in $MAIN; do
	printf '%s: %s $(LIST)\n' "${i/%.c/}" "${i/%.c/.o}" >>Makefile
done
if [ "$DEP" == yes ]; then
	for i in $FILES; do
		printf '%s\n\t$(CC) -c %s -o $@ $(CFLAGS)\n' "$(cpp -MM $CFLAGS $LDLIBS "$i")" "$i" >>Makefile
	done
else
cat <<'EOF' >>Makefile
%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)
EOF
fi
cat <<'EOF' >>Makefile
clean:
	rm -f $(MAIN) $(OBJECTS)
EOF
