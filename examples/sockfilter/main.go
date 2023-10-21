//go:build linux

// Sample output:
//
// examples# go run -exec sudo ./sockfilter -i enp0s1
// 2023/10/21 17:09:34 enp0s1  TCP    192.168.64.19   5632   -> 192.168.64.1    47071
// 2023/10/21 17:09:34 enp0s1  TCP    192.168.64.1    47071  -> 192.168.64.19   5632

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags "linux" -type event bpf sockfilter.c -- -I../headers

type Config struct {
	Iface string
}

var (
	config      Config
	indexToName map[int]string
	mu          lock.RWMutex
)

// htons converts the unsigned short integer hostshort from host byte order to network byte order.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func GetIfIndex(ifName string) (uint32, error) {
	iface, err := netlink.LinkByName(ifName)
	if err != nil {
		return 0, err
	}
	return uint32(iface.Attrs().Index), nil
}

func InitIndexToName() error {
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}

	indexToName = make(map[int]string, len(links))
	for _, link := range links {
		indexToName[link.Attrs().Index] = link.Attrs().Name
	}

	return nil
}

func init() {
	if err := InitIndexToName(); err != nil {
		log.Fatalf("failed to get ifname: %v", err)
	}
}

func LookupName(ifIndex int) string {
	mu.RLock()
	defer mu.RUnlock()

	name, ok := indexToName[ifIndex]
	if ok {
		return name
	}
	return "nil"
}

func OpenRawSock(index int) (int, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{
		Ifindex:  index, // 0 matches any interface
		Protocol: htons(syscall.ETH_P_ALL),
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}

// AttachSocketFilterByFD attach a socket filter to a function
func AttachSocketFilterByFD(fd int, program *ebpf.Program) error {
	var ssoErr error
	ssoErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_BPF, program.FD())
	if ssoErr != nil {
		return ssoErr
	}
	return nil
}

func ProtoString(proto int) string {
	// proto definitions:
	// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	protoStr := fmt.Sprintf("UNKNOWN#%d", proto)
	switch proto {
	case syscall.IPPROTO_TCP:
		protoStr = "TCP"
	case syscall.IPPROTO_UDP:
		protoStr = "UDP"
	case syscall.IPPROTO_ICMP:
		protoStr = "ICMP"
	}
	return protoStr
}

func main() {
	flag.StringVarP(&config.Iface, "interface", "i", "any", "interface to capture")
	flag.Parse()

	ifIndex, _ := GetIfIndex(config.Iface)
	log.Printf("get ifname %s ifindex: %d", config.Iface, ifIndex)

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	fd, err := OpenRawSock(int(ifIndex))
	if err != nil {
		log.Fatalf("unable to open a raw socket: %s", err)
		return
	}
	defer syscall.Close(fd)

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err = loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach ebpf program to a socket
	err = AttachSocketFilterByFD(fd, objs.bpfPrograms.BpfSocketHandler)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("eBPF program loaded and attached on socket")

	rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	log.Printf("%-15s %-6s -> %-15s %-6s %-6s",
		"interface",
		"protocol",
		"src",
		"->",
		"dst",
	)
	go readLoop(rd)

	// Wait
	<-stopper
}

func readLoop(rd *ringbuf.Reader) {
	// bpfEvent is generated by bpf2go.
	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), internal.NativeEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		log.Printf("%-6s  %-6s %-15s %-6d -> %-15s %-6d",
			LookupName(int(event.Ifindex)),
			ProtoString(int(event.IpProto)),
			intToIP(event.SrcAddr),
			event.Port16[0],
			intToIP(event.DstAddr),
			event.Port16[1],
		)
	}
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	//binary.BigEndian.PutUint32(ip, ipNum)
	binary.LittleEndian.PutUint32(ip, ipNum)
	return ip
}
