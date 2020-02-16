cc=gcc
OBJS=main.o netutil.o
SRCS=$(OBJS:%.o=%.c)
CLAGS=-g -O0 -Wall
LDLIBS=
TARGET=bridge
$(TARGET):$(OBJS)
	$(CC) $(CLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)