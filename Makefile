all:
	gcc *.c -o main.out && ./main.out
renesas:
	rl78-elf-gcc -std=gnu99 -DBLAKE2_NO_UNROLLING -Os -Wall -Wextra *.c -o renesas.out
clean:
	rm -rf *.out
