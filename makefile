LDLIBS=-lpcap
CXXFLAGS += -Iinclude

all: send-arp-spoofing


main.o: include/mac.h include/ip.h include/ethhdr.h include/arphdr.h main.cpp

arphdr.o: include/mac.h include/ip.h include/arphdr.h arphdr.cpp

ethhdr.o: include/mac.h include/ethhdr.h ethhdr.cpp

ip.o: include/ip.h ip.cpp

mac.o : include/mac.h mac.cpp

send-arp-spoofing: main.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp-spoofing *.o
