OUT=bin/main
SRC = $(wildcard src/*.cpp)
FLAGS = -O3 -I./src -std=c++17

$(OUT): main.cpp $(SRC)
	@mkdir -p bin
	g++ $(FLAGS) $^ -o $@

.PHONY: clean
clean:
	rm bin/*

.PHONY: run
run: $(OUT)
	$(OUT)
