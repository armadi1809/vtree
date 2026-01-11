.PHONY: test bench-gpu generate-data clean

test:
	futhark test test/test_operations.fut

bench-gpu:
	futhark bench benchmarks/benchmark_operations.fut --backend=cuda

benchmarks/bench: benchmarks/benchmark_operations.fut
	futhark c benchmarks/benchmark_operations.fut -o benchmarks/bench

generate-data: benchmarks/bench
	mkdir -p benchmarks/data
	echo "10000 42" | ./benchmarks/bench -e gen_random_tree -b > benchmarks/data/random_10k.in
	echo "50000 42" | ./benchmarks/bench -e gen_random_tree -b > benchmarks/data/random_50k.in
	echo "100000 42" | ./benchmarks/bench -e gen_random_tree -b > benchmarks/data/random_100k.in
	echo "250000 42" | ./benchmarks/bench -e gen_random_tree -b > benchmarks/data/random_250k.in
	echo "500000 42" | ./benchmarks/bench -e gen_random_tree -b > benchmarks/data/random_500k.in
	echo "1000000 42" | ./benchmarks/bench -e gen_random_tree -b > benchmarks/data/random_1m.in

clean:
	rm -f benchmarks/bench
	rm -rf benchmarks/data
	rm -rf benchmarks/*.c
	rm -rf test/*.c
	rm -rf test/test_operations