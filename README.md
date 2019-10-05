# Overview #

ICMPmonitor pings a set of hosts, executing per-host, user-defined commands
whenever a host begins or ceases to respond.

Assuming your build environment is suitable, build and execute the example
configuration with the following commands.

    % make clean && make
    % sudo ./icmpmonitor -f ./icmpmonitor.ini -v


# Status #

Complete. Tested on FreeBSD and Debian Linux.


# Instructions #

After editing the `Makefile` to suit your environment, build ICMPmonitor with
`make clean && make`. Copy the resulting `icmpmonitor` binary somewhere
suitable and create a configuration file based on the examples in
`icmpmonitor.ini`.

Execute ICMPmonitor as shown below, adding any additional flags desired. Note
that ICMPmonitor requires permission to send and receive network packets.

    % sudo icmpmonitor -f /path/to/config/file.ini


# Reference: Command Line Flags #

    -f <file>  Required. Pathname of configuration file.

    -v         Enable verbose mode, printing a message for each packet
               sent/received as well as each host up/down event.

    -r         Repeat `down_cmd` every time a downed host fails to respond to
               a ping. This contrasts with the default behavior which executes
               `down_cmd` only once per downed host event, requiring a ping
               response to complete the event before `down_cmd` can repeat.

    -h         Prints simple help information and exits.


# Reference: Configuration File Format #

Each host to be monitored should have a corresponding `host entry` in the
configuration file. This entry consists of a label in square brackets and a
series of mandatory configuration options. Comments may be included and are
demarked with pound signs. For example:

    [Example entry for localhost]
    host = 127.0.0.1
    interval = 2
    max_delay = 30
    up_cmd = "echo host up"  # This is a comment.
    down_cmd = "echo host down"
    start_condition = down

The `host` option references the host to be monitored and can be either an IP
address or fully-qualified hostname.

The `interval` specifies the number of seconds between pings. Values smaller
than TIMER_RESOLUTION as `#defined`ed in `icmpmonitor.c` will result in a ping
sent roughly once every `TIMER_RESOLUTION` seconds.

Hosts will only be marked down after missing all pings sent in the last
`max_delay` seconds.

After a host misses all pings sent in the last `max_delay` seconds, the
`down_cmd` is executed. Upon receipt of a response from the host, the `up_cmd`
is executed and all counters are reset.

The initial state ICMPmonitor should assume is specified by `start_condition`.
This can be important if the external commands executed for up/down events have
significant consequences. Allowed values are `up` or `down`.
