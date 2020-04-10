all:
	gcc main.c -o main.out && ./main.out
clean:
	rm -rf *.out
