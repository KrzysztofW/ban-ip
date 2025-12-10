Upstream Author: Krzysztof Witek

Copyright:
	 Copyright (c) 2025 Krzysztof Witek

License: GPL-2

Overview
========

ban-ip is a lightweight Linux C daemon designed to automatically block TCP port scans in real time.
It works by monitoring honeypot ports or Netfilter NFQueues and dynamically adding iptables rules to block offending IP addresses the moment a scan is detected.

ban-ip is ideal for servers, routers, embedded devices, or any Linux host that needs minimal-overhead network protection against automated attackers.

Features
========

TCP Honeypot Mode
-----------------

Listens on one or more TCP ports.
When a remote host connects, ban-ip:

- Detects the scan attempt.
- Immediately bans the offender by inserting an iptables rule.

Useful for classic port-scan and banner-grab detection.

Does not interfere with legitimate services (honeypot ports should be unused).

NFQueue SYN-Detection Mode
--------------------------

More efficient and stealthy than binding to TCP ports.
ban-ip can attach to an iptables NFQUEUE rule.
Blocks scanners on the first SYN packet, without creating a socket or completing a TCP handshake.
Lower overhead and faster reaction time.

Iptables Integration
--------------------

Adds DROP rules to:

- INPUT chain (local protection)
- FORWARD chain (router/firewall mode)

- Supports IPv4 (iptables)

Lightweight
-----------

Written in C with no heavy dependencies.
Designed as a small, efficient daemon.

Dependencies
============

In order to compile ban-ip you need these packets:

- libconfig-dev
- libnetfilter-queue-dev

Example configuration file
==========================

..

  /* ban-ip server configuration file */

  listen_port = 7777; /* used for administration */
  bind_address = "127.0.0.1"; /* used for administration */
  ip_whitelist = "";
  trap_ports = "445 23";
  iptables_chains = "INPUT FORWARD";
  fork = true;
  nfqueue_number = 99;
