all:
	gcc *.c -Wall -Wextra -o main.out && ./main.out
re:
	rl78-elf-gcc -std=gnu99 -DBLAKE2_NO_UNROLLING  -Os -o re.out *.c
	rl78-elf-run ./re.out
	#rl78-elf-gcc -std=gnu99 -DBLAKE2_NO_UNROLLING -Os -Wall -Wextra -c main.c
	#rl78-elf-gcc -std=gnu99 -DBLAKE2_NO_UNROLLING -Os -Wall -Wextra -c monocypher.c
	#rl78-elf-gcc -o re.out -Os main.o monocypher.o
	#rl78-elf-strip monocypher.o
clean:
	rm -rf *.out *.o
