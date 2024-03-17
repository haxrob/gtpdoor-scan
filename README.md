# GTPDOOR Scanner
A network scanner to scan for hosts infected with the GTPDOOR malware. Technical writeup [here](https://doubleagent.net/telecommunications/backdoor/gtp/2024/02/27/GTPDOOR-COVERT-TELCO-BACKDOOR).

Three detection methods supported:
 1. ACK scan (detects GTPDOOR v2)
 2. TCP connect scan (detects GTPDOOR v2)
 3. GTP-C GTPDOOR message type 0x6 (detects GTPDOOR v1 + v2) if default hardcoded key has not been changed

Note that for 1+2, the GTPDOOR implant must have ACLs configured for it's TCP RST/ACK beacon to respond.
Given these conditions, it cannot be guaranteed that GTPDOOR will be detected alone from active network scanning. 

# Usage
## Installation
Compiled 64-bit Linux executable available [here](https://github.com/haxrob/gtpdoor-scan/releases/), or build yourself:
```
go install github.com/haxrob/gtpdoor-scan@latest
```
## Running 
```
usage: ./gtpdoor-scan [options] <targets>
options:
  -a, --ack            ACK scan method - may work when inline firewall is stateless
      --all            Use all scan methods (--gtp, --ack, --connect)
  -c, --connect        Connect scan method (slow) - port specified must be open
  -f, --file string    Optional filename with list of targets (ip or subnets) per newline
  -g, --gtp            Attempt GTPDOOR msg type 6 (ACL query) over GTP-C 2123 using default key
  -h, --help           this message
  -i, --iface string   interface to receive responses (default "any")
      --passive        Scan for GTPDOOR with another scanner but listen and to detection here.
  -p, --ports string   TCP port numbers, separated by a comma (default "22")
  -r, --rate int       Rate limit (packets per second) (default 1000)
  -t, --timeout int    TCP connect() mode timeout (seconds) (default 1)
  -w, --workers int    Parallel scan worker threads (default 10)

<targets> is list of IP addresses or subnets

example: ./gtpdoor-scan --ack --ports 21,211 --gtp 192.168.0.0/24 10.2.1.1
example: ./gtpdoor-scan --all -f targets.txt
```

Using `--all` will initiate all three scan modes (`--gtp`,`--connect`, `--ack`). 
A note on the TCP connect scan, a target's TCP port must be responding. For the ACK mode, any arbitrary port can be chosen. It is assumed that that GTPDOOR is designed to support beaconing when the infected host is behind a stateful firewall with at least one TCP port open by using a connect scan, or a stateless firewall with an ACK scan.

__NOTE__: The GTPDOOR message scan `--gtp` only attempts to invoke GTPDOOR's ACL query message type and not the remote code execution message in order to avoid arbitrary code execution. The contents of the GTP message response is discarded. That said, if you do not have permission to scan assets with GTPDOOR and do so, you could get into trouble. 

Only run this tool against assets you are authorized to do so. Security researchers without prior permission may want to consider avoiding the `--gtp` flag. 

### External network scanner support
`gtpdoor-scan` can also be used alongside an external network scanner such as nmap or masscan by using the `--passive` switch. For example, nmap's [TCP ACK Scan](https://nmap.org/book/scan-methods-ack-scan.html) could be run while `gtpdoor-scan` is running on the same host in passive mode. While nmap may report the port as `unfiltered`, `gtpdoor-scan` will report that it received a possible beacon, indicating that GTPDOOR may have been running on the remote host.

```
$ gtpdoor-scan --passive &
$ nmap -sA <target>
```

Note that with a TCP connect scan, the port MUST be open as GTPDOOR expects to receive an ACK message. 

# Additional information
GTPDOOR version 2 will respond with a TCP ACK/RST message with the URG flag not set but the urgent TCP field set to 0x01 on recieving a TCP ACK either from a TCP three way handshake (`--connect` parameter) or a single ACK (`--ACK` parameter) ingress ACK packet.
A TCP ACK/RST will also be sent for a TCP SYN message but the urgent field will be set to zero. This condition is not considered a GTPDOOR beacon and is ignored.

GTPDOOR version 1 does not support TCP probe/beacons. The detection method implemented here is to send a GTPDOOR GTP-C message with the message type of 0x06 which is a GTPDOOR ACL query message (`--gtp` parameter). The default auth/encryption key is used.


