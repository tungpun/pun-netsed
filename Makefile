all: pun-netsed

pun-netsed: pun-netsed.o
	gcc pun-netsed.o -o pun-netsed -lnetfilter_queue

pun-netsed.o: pun-netsed.c
	gcc -Wall -c pun-netsed.c

clean:
	rm -f pun-netsed.o pun-netsed

