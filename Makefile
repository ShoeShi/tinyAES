CC = g++
CFLAGS = -Wall
LDLIBS =
LDFLAGS = 
SRCS = $(wildcard *.cpp)
HDRS = $(wildcard *.h)
OBJS = $(SRCS:.cpp=.o)
EXE = aes

all: $(EXE)

$(EXE): $(OBJS) 
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $(EXE) $(LDLIBS)

%.o: %.cpp helper.h order32.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)
	rm -f *~
	rm -f $(EXE)
