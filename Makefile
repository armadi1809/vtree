.PHONY: test bench-gpu generate-data clean all lib benchmarks/bench

test: lib
	futhark test test/test_operations.fut

bench-gpu: generate-data
	futhark bench benchmarks/benchmark_operations.fut --backend=cuda

benchmarks/bench: lib benchmarks/benchmark_operations.fut
	futhark c benchmarks/benchmark_operations.fut

generate-data: benchmarks/bench
	mkdir -p benchmarks/data
	echo "10000 42" | ./benchmarks/benchmark_operations -e gen_random_tree -b > benchmarks/data/random_10k.in
	echo "100000 42" | ./benchmarks/benchmark_operations -e gen_random_tree -b > benchmarks/data/random_100k.in
	echo "1000000 42" | ./benchmarks/benchmark_operations -e gen_random_tree -b > benchmarks/data/random_1m.in
	echo "10000000 42" | ./benchmarks/benchmark_operations -e gen_random_tree -b > benchmarks/data/random_10m.in

lib:
	futhark pkg sync
clean:
	rm -f benchmarks/benchmark_operations
	rm -rf benchmarks/data
	rm -rf benchmarks/*.c
	rm -rf test/*.c
	rm -rf test/test_operations
all: test bench-gpu