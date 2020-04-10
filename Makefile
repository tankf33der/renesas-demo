all:
	gcc *.c -Wall -Wextra -o main.out && ./main.out
re:
	rl78-elf-gcc -std=gnu99 -DBLAKE2_NO_UNROLLING -Os -ffloat-store -ffunction-sections -fno-inline-functions -fno-defer-pop -fno-peephole *.c
	#rl78-elf-gcc -std=gnu99 -DBLAKE2_NO_UNROLLING -Os -Wall -Wextra -c main.c
	#rl78-elf-gcc -std=gnu99 -DBLAKE2_NO_UNROLLING -Os -Wall -Wextra -c monocypher.c
	#rl78-elf-strip monocypher.o
clean:
	rm -rf *.out *.o
