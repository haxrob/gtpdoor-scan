/*
GTPDOOR scanner - https://github.com/haxrob/gtpdoor-scan

Author: https://x.com/haxrob
Version: 0.1

Three detection methods supported:
 1. ACK scan (detects GTPDOOR v2)
 2. TCP connect scan (detects GTPDOOR v2)
 3. GTP-C GTPDOOR message type 0x6 (detects GTPDOOR v1 + v2) if default key not changed

Note that for 1+2, the GTPDOOR implant must have ACLs configured for it's TCP RST/ACK beacon to respond.
Given these conditions, the scanner cannot guarantee it will always find GTPDOOR running.

See: https://doubleagent.net/telecommunications/backdoor/gtp/2024/02/27/GTPDOOR-COVERT-TELCO-BACKDOOR
*/
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/routing"

	flag "github.com/spf13/pflag"
)

const _DEBUG bool = false

// GTPDOOR v2 TCP beacon
type beacon struct {
	ip  *layers.IPv4
	tcp *layers.TCP
	buf gopacket.SerializeBuffer
}

// command line options
type options struct {
	ackScan     bool
	connectScan bool
	passive     bool
	gtptry      bool
	iface       string
	ports       string
	targetfile  string
	timeout     int
	rateLimit   int
	workers     int
	useall      bool
}

type Scanner struct {
	router     routing.Router
	conn       net.PacketConn // SYN
	udpConn    *net.UDPConn   //  GTP messages
	opts       *options
	numWorkers int
	timeout    time.Duration
	done       chan bool
	handle     *pcap.Handle
	cancel     context.CancelFunc
	context    context.Context  // pcap handler termination
	limiter    <-chan time.Time // packets per second
}

type host struct {
	addr net.IP
	port uint16
}

type gtpdoor struct {
	GtpHeader [8]uint8 // we only care about GTP version byte
	Padding   [9]uint8
	Key       uint32
	MsgType   uint8
	MsgLen    uint16
}

func (h host) String() string {
	return fmt.Sprintf("%s:%d", h.addr.String(), h.port)
}

func newScanner(opts options) (*Scanner, error) {

	// router will give us the source address for when we build a raw ACK packet
	router, err := routing.New()
	if err != nil {
		return nil, err
	}
	scanner := &Scanner{
		router:     router,
		numWorkers: opts.workers,
		timeout:    time.Second * time.Duration(opts.timeout), // for TCP connect method
		limiter:    time.Tick(time.Second / time.Duration(opts.rateLimit)),
	}

	// for ACK scan method
	// the tx queue will fill up for large scans, perhaps should use gopacket for this
	scanner.conn, err = net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	// GTPDOOR GTP message scan
	// should the source port be randomized?
	scanner.udpConn, err = net.ListenUDP("udp", &net.UDPAddr{Port: 12345})
	if err != nil {
		return nil, err
	}

	// the pcap listener is blocking, later version supports a context, although
	// this appears not to be pushed to google/gopacket repository, hence using gopacket/gopacket
	scanner.context, scanner.cancel = context.WithCancel(context.Background())

	// snaplen could be trimmed
	scanner.handle, err = pcap.OpenLive(opts.iface, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	return scanner, nil
}

// send raw ACK packet, this will trigger a beacon response from GTPDOOR if it's not behind a stateful firewall
func (s *Scanner) NewAckBeacon(dstip net.IP, dstport uint64) *beacon {
	b := &beacon{}

	// arbitrary source port, could randomize this or better, get the kernel to give us one
	srcport := layers.TCPPort(54322)
	iface, gw, src, err := s.router.Route(dstip)
	if err != nil {
		log.Fatal("routing error:", err)
	}
	if _DEBUG {
		log.Printf("new beacon ip %v with interface %v, gateway %v, src %v", dstip.String(), iface.Name, gw, src)
	}

	// IP header
	b.ip = &layers.IPv4{
		SrcIP:    src,
		DstIP:    dstip,
		Protocol: layers.IPProtocolTCP,
	}
	if _DEBUG {
		log.Printf("beacon tcp src port: %d, dst port: %d\n", srcport, dstport)
	}

	// TCP header. seq number 0 should be ok.
	b.tcp = &layers.TCP{
		SrcPort: srcport,
		DstPort: layers.TCPPort(dstport),
		ACK:     true,
		//SYN: true,
		//Seq:    1105024978,
		Seq:    0,
		Window: 1024,
	}
	b.tcp.SetNetworkLayerForChecksum(b.ip)

	b.buf = gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(b.buf, opts, b.tcp); err != nil {
		log.Fatal(err)
	}

	return b
}

func (s *Scanner) sendAckBeacon(h host) {
	tcpBeacon := s.NewAckBeacon(h.addr, uint64(h.port))
	if _, err := s.conn.WriteTo(tcpBeacon.buf.Bytes(), &net.IPAddr{IP: h.addr}); err != nil {
		log.Fatal(err)
	}
}

// TCP connect - GTPDOOR will respond with a beacon only if there is actually a port open that we connect to
func (s *Scanner) sendConnectBeacon(h host) {

	// here we just want to initiate a 3 way handshake so eventually we get an ACK to the target
	conn, err := net.DialTimeout("tcp", h.String(), s.timeout)
	if err == nil {
		conn.Close()
		return
	}
}

// Try to connect to GTPDOOR with the default hardcoded key. The message type here is 0x06 which returns the ACL
// here we will discard the contents (ACL) if it looks like we received a valid response
func (s *Scanner) sendGtpMsg(h host) {
	g := gtpdoor{
		GtpHeader: [8]uint8{0, 1, 0, 0, 0, 0, 0, 0},
		Padding:   [9]uint8{1, 2, 3, 4, 5, 6, 7, 8, 9},
		Key:       135798642,
		MsgType:   0x06,
	}
	var m bytes.Buffer
	binary.Write(&m, binary.LittleEndian, g)

	// GTP-C Port
	_, err := s.udpConn.WriteTo(m.Bytes(), &net.UDPAddr{IP: h.addr, Port: int(2123)})
	if err != nil {
		fmt.Println("error sending udp")
		return
	}

}

func (s *Scanner) fireAway(targets []host) {

	// hosts to scan
	targetChan := make(chan host)
	var wg sync.WaitGroup
	for i := 0; i < s.numWorkers; i++ {
		wg.Add(1)
		// for each worker ..
		go func(i int) {
			for t := range targetChan {
				if s.opts.gtptry {
					// blocking for rate limiting
					<-s.limiter
					s.sendGtpMsg(t)
				}
				if s.opts.ackScan {
					<-s.limiter
					s.sendAckBeacon(t)
				}
				if s.opts.connectScan {
					<-s.limiter
					s.sendConnectBeacon(t)
				}
			}
			wg.Done()
		}(i)

	}

	for _, h := range targets {
		targetChan <- h
	}
	close(targetChan)

	// all workers finished
	wg.Wait()

	// wait for a while for any more packets to be received before exiting
	time.Sleep(time.Second * 5)

	// signal to the pcapListen packet handler to stop blocking so we can terminate
	s.cancel()
}

func (s *Scanner) pcapListen() {
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())

	//handle.ReadPacketData() doesn't liked cooked packets (-i any) for some reason

	// context.Done() will return from PacktsCtx()
	for packet := range packetSource.PacketsCtx(s.context) {
		var ipv4 *layers.IPv4
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {

			// for the source address
			ipv4 = ipLayer.(*layers.IPv4)
		} else {
			continue
		}

		srcaddr := ipv4.SrcIP.String()

		// TCP connect() scan method
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			// GTPDOOR beacons will only have ACK and RST set
			if !(tcp.ACK && tcp.RST) {
				continue
			}
			// beacons have nothing but the TCP header
			if tcp.DataOffset != 0x05 {
				fmt.Println("invalid size")
				continue
			}

			dstport := tcp.DstPort.String()

			// This is somewhat of an invalid scenario? where the urgent flag is not set but the field is
			// so if we see this, it could be a good chance it's a GTPDOOR response
			if tcp.Urgent == 0x01 && !tcp.URG {
				fmt.Printf("[\033[92m+\033[0m] Received possible GTPDOOR TCP beacon from %s:%s\n", srcaddr, dstport)
			}

		}

		// GTP scan method
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			if udp.Length >= 20 && udp.SrcPort == 2123 {
				var m gtpdoor
				binary.Read(bytes.NewBuffer(udp.Payload), binary.LittleEndian, &m)

				// GTP_ECHO_RESPONSE + GTPDOOR MSG TYPE 6
				if m.GtpHeader[1] == 0x02 && m.MsgType == 0x06 {
					fmt.Printf("[\033[92m+\033[0m] Received GTPDOOR GTP-C message reply from %s:%d\n", srcaddr, udp.SrcPort)
				}
			}
		}
	}
}

// convert comma separated list of IPs or subnets into individual IPs with port numbers
func generateTargets(argList []string, ports string) []host {
	var portList []uint16
	var ipList []net.IP

	// returned list of hosts to scan
	var targets []host
	for _, p := range strings.Split(ports, ",") {
		if pInt, err := strconv.ParseUint(p, 10, 16); err == nil {
			portList = append(portList, uint16(pInt))
		}
	}
	for _, h := range argList {
		if h[len(h)-3] == '/' {
			expand := netExpand(h)
			ipList = append(ipList, expand...)
		} else {
			if ip := net.ParseIP(h); ip != nil {
				ipList = append(ipList, ip)
			}
		}
	}
	for _, ip := range ipList {
		for _, p := range portList {
			h := host{
				addr: ip,
				port: p,
			}
			targets = append(targets, h)
		}
	}
	// randomize IPs so requests are not sequential
	rand.Shuffle(len(targets), func(i, j int) {
		targets[i], targets[j] = targets[j], targets[i]
	})
	return targets

}

// subnet into IPs
func netExpand(network string) []net.IP {
	var ips []net.IP
	ip, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		log.Fatal(err)
	}
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ipcopy := make(net.IP, len(ip))
		copy(ipcopy, ip)
		ips = append(ips, ipcopy)
	}

	return ips[1 : len(ips)-1]
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func main() {
	opts := options{}
	flag.BoolVar(&opts.passive, "passive", false, "Scan for GTPDOOR with another scanner but listen and to detection here.")
	flag.BoolVarP(&opts.ackScan, "ack", "a", false, "ACK scan method - may work when inline firewall is stateless")
	flag.BoolVarP(&opts.connectScan, "connect", "c", false, "Connect scan method (slow) - port specified must be open")
	flag.BoolVarP(&opts.gtptry, "gtp", "g", false, "Attempt GTPDOOR msg type 6 (ACL query) over GTP-C 2123 using default key")
	flag.StringVarP(&opts.iface, "iface", "i", "any", "interface to receive responses")
	flag.StringVarP(&opts.ports, "ports", "p", "22", "TCP port numbers, separated by a comma")
	flag.StringVarP(&opts.targetfile, "file", "f", "", "Optional filename with list of targets (ip or subnets) per newline")
	flag.IntVarP(&opts.timeout, "timeout", "t", 1, "TCP connect() mode timeout (seconds)")
	flag.IntVarP(&opts.rateLimit, "rate", "r", 1000, "Rate limit (packets per second)")
	flag.IntVarP(&opts.workers, "workers", "w", 10, "Parallel scan worker threads")
	flag.BoolVar(&opts.useall, "all", false, "Use all scan methods (--gtp, --ack, --connect)")
	help := flag.BoolP("help", "h", false, "this message")
	flag.Parse()
	if *help {
		fmt.Println("GTPDOOR network scanner [@haxrob - https://github.com/haxrob/gtpdoor-scan]\n")
		fmt.Printf("usage: %s [options] <targets>\n", os.Args[0])
		fmt.Println("options:")
		flag.PrintDefaults()
		fmt.Printf("\n")
		fmt.Println("<targets> is list of IP addresses or subnets\n")
		fmt.Printf("example: %s --ack --ports 21,22 --gtp 192.168.0.0/24 10.2.1.1\n", os.Args[0])
		fmt.Printf("example: %s --all -f targets.txt\n\n", os.Args[0])
		os.Exit(0)
	}
	if !opts.passive && (len(flag.Args()) == 0 && opts.targetfile == "") {
		fmt.Println("Must specify at least one target!")
		os.Exit(1)
	}
	if !opts.useall && !opts.passive && (!opts.ackScan && !opts.connectScan && !opts.gtptry) {
		fmt.Println("Must specific at least one or more scan type (--ack, -connect, --gtp) or just specify --all to try everything\n")
		os.Exit(1)
	}

	if opts.useall {
		opts.ackScan = true
		opts.connectScan = true
		opts.gtptry = true
	}

	var targs []string
	if opts.targetfile != "" {
		f, err := os.Open(opts.targetfile)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		bufscanner := bufio.NewScanner(f)
		for bufscanner.Scan() {
			h := bufscanner.Text()
			if len(h) < 8 {
				continue
			}
			targs = append(targs, h)
		}

	} else {
		targs = append(targs, flag.Args()...)
	}

	if os.Geteuid() != 0 {
		fmt.Println("root privs required, exiting ...")
		os.Exit(1)
	}

	// not really needed
	// tcp[13] == 0x14 = ACK + RST
	/*if err := handle.SetBPFFilter("tcp[13] == 0x14"); err != nil {
		panic(err)
	}*/

	scanner, err := newScanner(opts)
	if err != nil {
		panic("Unable to init scanner")
	}
	scanner.opts = &opts
	targets := generateTargets(targs, opts.ports)
	go scanner.pcapListen()

	// loop forever
	if opts.passive {
		fmt.Println("INFO: Passive mode. Run external network scanner in another terminal. ")
		fmt.Println("      e.g. nmap -sA for ACK scans, nmap -sC for TCP connect scans.")
		fmt.Println("\nDetected GTPDOOR beacons will be shown here. CTRL-C to exit")
		select {}
	}

	fmt.Printf("INFO: %d hosts added to target list\n", len(targets))
	fmt.Printf("INFO: parallel workers: %d\n", opts.workers)
	fmt.Printf("INFO: enabled scan modes: ACK [%v], CONNECT [%v], GTP [%v]\n", opts.ackScan, opts.connectScan, opts.gtptry)

	if opts.ackScan || opts.connectScan {
		fmt.Printf("INFO: TCP destination port: %s\n", opts.ports)
	}

	// Give some time before init'ing scan. Not sure if this is really needed.
	time.Sleep(time.Second * 1)

	fmt.Println("\nStarting scanning ... ")
	scanner.fireAway(targets)

	select {

	// set when the context is closed after all hosts scanned
	case <-scanner.context.Done():
		fmt.Println("\nFinished, exiting ...")
		return
	}
}
