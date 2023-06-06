LDLIBS=-lpcap

all: airodump

airodump: main.o mac.o dot11.o
	$(LINK.cc) $^ $(LDLIBS) -o $@

clean:
	rm -f *.o airodump