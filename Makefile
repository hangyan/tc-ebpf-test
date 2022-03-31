build:
	clang -O2 -Wall -target bpf -c bar.c -o bar.o
all: build