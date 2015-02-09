# pypcpc

This is a Port Control Protocol(PCP) command line client/lib in python.
Only supports PCPv2.

Following PCP opcodes are supported:
* MAP (RFC6887)
* PEER (RFC6887)
* ANNOUNCE (RFC6887)
* GET (draft-boucadair-pcp-failure-06)

Following PCP options are supported:
* THIRD_PARTY (RFC6887)
* PREFER_FAILURE (RFC6887)
* FILTER (RFC6887)
* DESCRIPTION (draft-boucadair-pcp-extensions-03)
* PORT_RESRV (#draft-boucadair-pcp-rtp-rtcp-05)
* NEXT v2 (draft-boucadair-pcp-failure-06)

Target for developer and protocol testing.

## Installation

Require python 2.7 (python3 is not supported)

Should be able to run on both Windows and *nix

## Usage as a Command Line Client

As CLI client, pypcpc provides an interactive shell interface.

```
python pcpc.py -h
usage: pcpc.py [-h] [-d] -i SOURCE -s SERVER

PCPv2 Client by Hu Jun

optional arguments:
  -h, --help            show this help message and exit
  -d, --DEBUG           enable DEBUG output
  -i SOURCE, --source SOURCE
                        source address of requests
  -s SERVER, --server SERVER
                        PCP server address

```
specify the source and server to invoke the shell:
```
python pcpc.py -i 192.168.5.100 -s 192.168.5.1 -d
PCPv2 CLI Client by Hu Jun. Jan.2015
Ctrl+C to quit
PCPc>

```
type help to see available commands; "&lt;cmd&gt; -h" to see command specific help; use "&lt;cmd&gt;  &lt;arg&gt; -h" to see some argument specific help(e.g. "get -next -h")

```
PCPc>get -h
usage:  get [-h] [-proto PROTO] [-intip INTIP] [-extip EXTIP]
            [-intport INTPORT] [-extport EXTPORT] [-lt LIFETIME] [-next ...]

optional arguments:
  -h, --help            show this help message and exit
  -proto PROTO, --proto PROTO
                        Protocol number,udp=17,tcp=6
  -intip INTIP, --intIP INTIP
                        filter internal IP
  -extip EXTIP, --extIP EXTIP
                        filter external IP
  -intport INTPORT, --intPort INTPORT
                        Internal Port
  -extport EXTPORT, --extPort EXTPORT
                        External Port
  -lt LIFETIME, --lifetime LIFETIME
                        lifetime
  -next ..., --nextOption ...
                        next option. has to be last argument. -next -h for
                        further help
PCPc>get -next -h
usage: -next [-h] [-proto PROTO] [-me {1,0}] [-intip INTIP] [-extip EXTIP]
             [-intport INTPORT] [-extport EXTPORT] [-no NONCE]
             [-mo MAPOPTIONS]

optional arguments:
  -h, --help            show this help message and exit
  -proto PROTO, --proto PROTO
                        Protocol number,udp=17,tcp=6
  -me {1,0}, --moreend {1,0}
                        more/end
  -intip INTIP, --intIP INTIP
                        filter internal IP
  -extip EXTIP, --extIP EXTIP
                        filter external IP
  -intport INTPORT, --intPort INTPORT
                        Internal Port
  -extport EXTPORT, --extPort EXTPORT
                        External Port
  -no NONCE, --nonce NONCE
                        maping nonce, 12 byte hex str, 0x10abdf,default is all
                        0
  -mo MAPOPTIONS, --mapoptions MAPOPTIONS
                        maping options code-1/code-2/code-3...
```


## Usage as a Library
from pypcpc import asyncPCPClient

see comments in pypcpc.py for detail usage



## License
MIT
