all: dumbbell-sim

dumbbell-sim: dumbbell-sim.cc
	g++ -I/usr/include/ns3.17 -lns3.17-applications -lns3.17-internet -lns3.17-network -lns3.17-core -lns3.17-point-to-point -Wall dumbbell-sim.cc -o dumbbell-sim
