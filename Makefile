.PHONY: test bench-gpu clean all lib

test: lib
	futhark test test/test_operations.fut

bench-gpu:
	futhark bench benchmarks/benchmark_operations.fut --backend=cuda

lib:
	futhark pkg sync

clean:
	rm -f benchmarks/benchmark_operations
	rm -rf benchmarks/data
	rm -rf benchmarks/*.c
	rm -rf test/*.c
	rm -rf test/test_operations
all: test bench-gpu