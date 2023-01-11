all: r

r: sniffer.c
	gcc sniffer.c -o sniffer -lpcap

clean:
	rm -f *.o sniffer

run:
	./sniffer

