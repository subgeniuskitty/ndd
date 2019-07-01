NDD - Network Disk Daemon
=========================

Description
-----------

This is a user-space implementation of ND(4p) protocol, used by early SUN
diskless workstations to access data on servers over a network.

The ND protocol was most likely developed within Sun Microsystems Inc. in the
early 80s; it was later replaced by NFS in SunOS 4.x (around 1989). The protocol
is mentioned in some books and papers from 80s but its internals are described
only in man pages distributed with SunOS; this work is based on the version
distributed with SunOS 3.5.

The ND protocol is very simple: on the client it encapsulates block I/O requests
into IP datagrams and transmits them to the server. The server performs the I/O
and sends the reply back to the client. Each network "disk" on the server is
implemented as a dedicated raw disk partition (or slice). The protocol does not
provide any kind of access control or support for concurrent access: each client
is supposed to modify only its own data; shared data needs to be accessed
read-only.

This implementation uses files instead of disk slices and can run either as
a daemon or a foreground process. It was originally developed on Linux and
Solaris, but it should run on any modern UNIX-like system which provides
adequate support for SOCK_RAW/IPPROTO_IP sockets.

Status
------

Complete enough to use with real Sun hardware.

Installation
------------

Edit the `Makefile` and the user configurable `#define`s in `ndd.c`. Then run
`make` to produce a binary named `ndd`.
