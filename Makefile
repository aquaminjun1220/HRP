all: tproxy AA BB


tproxy: ./src/tproxy.cpp
	g++ -o ./build/tproxy ./src/tproxy.cpp -O2 -std=c++20

AA: ./src/AA.cpp
	g++ -o ./build/AA ./src/AA.cpp -O2 -std=c++20

BB: ./src/BB.cpp
	g++ -o ./build/BB ./src/BB.cpp -O2 -std=c++20