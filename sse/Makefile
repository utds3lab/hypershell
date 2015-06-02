obj = sse dispsys
CFLAGS = -Wall -fPIC
LDFLAGS = -shared
all:sse.so

sse.so:$(addsuffix .o,$(obj))
	gcc $(LDFLAGS)  $(addsuffix .o,$(obj)) -o $@
%.o:%.c
	gcc $(CFLAGS) -c $< 
clean:
	rm *.o
