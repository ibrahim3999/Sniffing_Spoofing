all: r

r: sniffer.c
	gcc -Wall -g -o sniff sniffer.c

clean:
	rm -f *.o sniff

run:
	./sniff

