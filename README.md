Simulation of a dumbbell topology using ns3 3.17
------------------------------------------------

dependencies (on Debian based distros):

	libns3-dev (= 3.17)

compilation:

	make

example execution:

	$ cat << END | ./dumbbell-sim > log
	UR TCP 536 0.0 1250
	UR TCP 536 250 500
	LR UDP 1000 750 1000 0.9Mbps
	END

The file `log` then contains traces with the first column being the timestamp,
the second column being the ns3 context and the third column being the traced
value of this context. The traced values are TCP congestion window size
changes, received packets and queue drops.

The traffic description is done via standard input. Each line represents one
flow and the dumbbell will be created such that it has as many clients on each
side as there are flows. Each flow will originate from a unique node N on the
left side of the dumbbell and reach node N on the right side of the dumbbell.
This way, every node is involved in exactly one flow and the connection in the
center of the dumbbell serves as the bottleneck.

So above example would create the following topology:

	 L1                R1
	   \              /
	    \+--+    +--+/
	L2---|LR|----|RR|---R2
	    /+--+    +--|\
	   /              \
	 L3                R3

The flow given in the first line would originate from `L1`, go through the
bottleneck link between the left and right router (`LR` and `RR`, respectively)
and end at `R1`. The flow given in the second line would go from `L2` to `R2`
and the last one from `L3` to `R3`.

Flow description format
-----------------------

Each line represents one flow between two unique nodes of the dumbbell, flowing
from left to right. Each line is split by their white spaces. The first element
represents the type of flow. There are three flow types.

**LR**: this type stands for "limited rate" and allows to specify traffic which
is limited by transmission rate. Start and stop times govern the duration of
this traffic.

**UR**: this type stands for "unlimited rate" and allows to specify traffic
which is sent as fast as possible. Only TCP traffic is allowed. Start and stop
times govern the duration of this traffic.

**LT**: this type stands for "limited transfer" and allows to specify traffic
which is sent as fast as possible. Only TCP traffic is allowed. The amount of
data to transfer governs when this flow stops transmitting.

The second element in each line is the transport type an can be either "TCP" or
"UDP". Observe the restrictions of transport type with respect to the flow
type.

The third element is the package size to send. For TCP traffic this will also
adapt the segment size of the underlying socket.

The fourth element is the start time of the flow given in seconds.

For `LR` and `UR` flow types, the fifth element is the stop time given in
seconds. For the `LT` type, the fifth element is the maximum transfer size,
given in bytes. For all types, the fifth element governs when the flow will
stop.

The `LR` type takes a sixth element, specifying the desired transmission rate.
This value is given with a unit like "Mbps".

Commandline Arguments
---------------------

While flow descriptions are read from standard input, commandline arguments
allow to setup properties of the dumbbell topology. By default, the error rate
of the involved links is 0.0, which means no packet is dropped by the physical
links. The default TCP congestion-avoidance algorithm is NewReno and other
options are Tahoe, Reno, Westwood and WestwoodPlus. The default bandwith and
latency of the bottleneck link is 1Mbps and 50ms, respectively. The default
bandwidth and latency of the access links of the nodes to the routers is 10Mbps
and 1ms, respectively.

When giving an error rate other than 0.0, a random element is introduced. It is
possible to make this randomness deterministic by using the `--run` option
which allows to make deterministic runs with the same outcome, given the same
run number.

Depending on the flow definitions you might want to start the simulation early.
This is possible with the `--simstop` argument.

You can enable pcap tracing of all links with the `--tracing` option.
