all: nfqnl-test

nfqnl-test: nfqnl_test.cpp
	g++ -o nfqnl-test nfqnl_test.cpp -lnet -lnetfilter_queue

clean:
	rm -f *.o nfqnl-test
