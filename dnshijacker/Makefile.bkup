all: ask_dns answer_dns dnshijacker

ask_dns:
	gcc ask_dns.c -lnet `libnet-config --defines` -o ask_dns

answer_dns:
	gcc answer_dns.c -lnet `libnet-config --defines` -o answer_dns

dnshijacker:
	gcc dnshijacker.c -lpcap -lnet -lresolv `libnet-config --defines` -o dnshijacker

debug:
	gcc dnshijacker.c -lpcap -lnet -lresolv `libnet-config --defines` -o dnshijacker -DDEBUG -ggdb

clean:
	rm -f core ask_dns answer_dns dnshijacker

rm:
	rm -f core ask_dns* answer_dns* dnshijacker*
