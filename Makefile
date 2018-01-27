all:
	$(CC) -o sniffcon -lpcap sniffcon.c sniff.c stat.c

clean:
	rm -f sniffcon
