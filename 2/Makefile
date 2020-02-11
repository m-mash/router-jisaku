OBJS=ltest.o
SRCS=$(OBJS:%.=%.c)
CFLAGS=-g -Wall
LDLIBS=
TARGET=ltest
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDLIBS) -o $(TARGET) $(OBJS) $(LDLIBS)