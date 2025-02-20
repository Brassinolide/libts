CXX = g++

CXXFLAGS = -fPIC -O2 -fvisibility=hidden -Iopenssl/linux/include

LDFLAGS = -Lopenssl/linux/lib64 -lcrypto -lssl

TARGET = libts.so

SRCS = main.cpp

OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -shared -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
