Sirin Sniffer
=============

Description
-----------

It's a test task repo for Sirin Software.
The application is a packet sniffer that performs incoming packet stats collection. The sniffer is
composed of daemon and CLI (for interaction with daemon and stats printing).


Building
--------

Building the sniffer is pretty straightforward:

```bash
    $ make
```

Cleaning built files:

```bash
    $ make clean
```


Usage
-----

"sniffcon" program is a CLI for daemon control. Usage:

```bash
    $ ./sniffcon <command/--help> ...
```

Possible commands:

* start [iface] — starts the daemon on "iface" (or the current interface, if omitted)
* stop — terminates daemon process (and flushes stats to disk)
* show [ip] count — shows count of received packets for an IPv4 address "ip"
* select iface [iface] — switches interface being sniffed to "iface" (NYI, whoops)
* stat [iface] — prints stats for packets on "iface" (or globally, if omitted)
* reset — resets packets stats
* --help — prints this message

Running daemon is also possible by just running "sniffer" executable:

```bash
    $ ./sniffer [iface]
```

Possible issues
---------------

* "select" command is to be implemented
* possible memory leaks in stats struct allocation and filename concat operations (will fix)
