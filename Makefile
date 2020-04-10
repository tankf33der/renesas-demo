all:
	gcc *.c -Wall -Wextra -o main.out && ./main.out
renesas:
	rl78-elf-gcc -v -g -std=gnu99 -DBLAKE2_NO_UNROLLING -O1 -Wall -Wextra *.c
	#rl78-elf-gcc -std=gnu99 -DBLAKE2_NO_UNROLLING -Os -Wall -Wextra -c main.c
	#rl78-elf-gcc -std=gnu99 -DBLAKE2_NO_UNROLLING -Os -Wall -Wextra -c monocypher.c
	#rl78-elf-strip monocypher.o
clean:
	rm -rf *.out *.o
