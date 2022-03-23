build: 
    clang -O2 -emit-llvm -c main.c -o - | llc -march=bpf -mcpu=probe -filetype=obj -o main.o