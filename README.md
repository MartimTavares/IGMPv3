# IGMPv3

Bachelor's Final Year Project - IST 2021/2022

### Team Members

| Number | Name              | User                                        | Email                                             |
|--------|-------------------|---------------------------------------------|---------------------------------------------------|
| 96758  | Martim Tavares    | <https://github.com/MartimTavares>          | <mailto:martim.tavares@tecnico.ulisboa.pt>        |



## Getting Started

The overall system is made up of several modules. The definition of the messages' headers and packets is in the _Packet_ folder. 
The next steps will be implementing the business logic from which the protocol was made for.

See the [IGMPv3 RFC](https://datatracker.ietf.org/doc/html/rfc3376) for a wider view of the protocol's potential and 
requirements in order to fully achieve its own purpose.

### Prerequisites

The Project is configured with _Python_ _3_. This project also needs the assistance of Kathará to simulate the network scenario. The 
network devices are emulated by containers interconnected by virtual Layer-2 LANs, using either Docker or Kubernetes as backend 
virtualization system. Follow the steps at [doccker install guide](https://docs.docker.com/get-docker/) to install _Docker_ and
[Kathará](https://www.kathara.org) to install the network emulator.

To confirm that you have them installed and which versions they are, run in the terminal:

```s
python -version
```

### Execution

Python compiles on its own and therefore all it is needed to run the program is to write the following commands in Kathará's 
router terminal:

(1) To start using the code you must start by running the emulated network. To do so, run the following commands:

```s
cd IGMPv3/kathara_network/emulation
kathara lstart
```

(2) The next step is to copy the code’s directory into the OS of each routing device.
For that you should configure kathara to allow the sharing of files between the hosting OS (your own) and the emulated OS of the router. After this configuration run the command:

```s
cp /hosthome/(your OS path to the igmp directory)/IGMPv3/Router/igmpv3/ . -r
cd igmpv3/
```

(3) Finally, run the command to start the Python code:

```s
python main.py
```
