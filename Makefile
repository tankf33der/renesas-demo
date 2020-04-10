all:
	gcc *.c -DUSE_ED25519 -o main.out && ./main.out
renesas:
	rl78-elf-gcc  -fdata-sections  -std=gnu99 -DBLAKE2_NO_UNROLLING -Os -Wall -Wextra *.c
	#rl78-elf-gcc -std=gnu99 -DBLAKE2_NO_UNROLLING -Os -Wall -Wextra -c main.c
	#rl78-elf-gcc -std=gnu99 -DBLAKE2_NO_UNROLLING -Os -Wall -Wextra -c monocypher.c
	#rl78-elf-gcc -std=gnu99 -DBLAKE2_NO_UNROLLING -Os -Wall -Wextra -c monocypher-ed25519.c
	#rl78-elf-strip monocypher.o
clean:
	rm -rf *.out *.o
