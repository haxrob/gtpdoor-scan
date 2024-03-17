# GTPDOOR Scanner
A network scanner to scan for hosts infected with the GTPDOOR malware. Technical writeup [here](https://doubleagent.net/telecommunications/backdoor/gtp/2024/02/27/GTPDOOR-COVERT-TELCO-BACKDOOR).

Three detection methods supported:
 1. ACK scan (detects GTPDOOR v2)
 2. TCP connect scan (detects GTPDOOR v2)
 3. GTP-C GTPDOOR message type 0x6 (detects GTPDOOR v1 + v2) if default hardcoded key ihas not been changed

Note that for 1+2, the GTPDOOR implant must have ACLs configured for it's TCP RST/ACK beacon to respond.
Given these conditions, it cannot be guaranteed that GTPDOOR will be detected from active network scanning. 

# Usage
## Installation
Compiled 64-bit Linux executable available [here](https://github.com/haxrob/gtpdoor-scan/releases/), or build yourself:
```
go install github.com/haxrob/GTPDOOR-SCAN/@latest
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

# Additional information
GTPDOOR version 2 will respond with a TCP ACK/RST message with the URG flag not set but the urgent TCP field set to 0x01 on recieving a TCP ACK either from a TCP three way handshake (`--connect` parameter) or a single ACK (`--ACK` parameter) ingress ACK packet.
A TCP ACK/RST will also be sent for a TCP SYN message but the urgent field will be set to zero. This condition is not considered a GTPDOOR beacon and is ignored.

GTPDOOR version 1 does not support TCP probe/beacons. The detection method implemented here is to send a GTPDOOR GTP-C message with the message type of 0x06 which is a GTPDOOR ACL query message (`--gtp` parameter). The default auth/encryption key is used.


