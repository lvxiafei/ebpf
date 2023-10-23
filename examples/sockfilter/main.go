//go:build linux

// Sample output:
//
// examples# go run -exec sudo ./sockfilter -i enp0s1
// 2023/10/21 23:20:20 enp0s1 TCP  HOST     | fa:4d:89:b9:2d:64 > 52:54:00:cb:05:af | 192.168.64.19 | 192.168.64.1 > 192.168.64.19 | 43981 > 5632
// 2023/10/21 23:20:20 enp0s1 TCP  OUTGOING | 52:54:00:cb:05:af > fa:4d:89:b9:2d:64 | 192.168.64.1  | 192.168.64.19 > 192.168.64.1 | 5632  > 43981

package main

import (
	"bufio"
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
	"strings"
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

const (
	// proto
	IPPROTO_VRRP             = 0x70
	IPPROTO_PGM              = 0x71
	IPV6_MAX_SOCK_SRC_FILTER = 0x80
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
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL))) // ETH_P_ALL, 表示能够接收本机收到的所有二层报文，包括IP，ARP，自定义二层报文等
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
	case syscall.IPPROTO_UDP: // 0x11
		protoStr = "UDP"
	case syscall.IPPROTO_ICMP:
		protoStr = "ICMP"
	case IPPROTO_VRRP:
		protoStr = "VRRP"
		//case IPV6_MAX_SOCK_SRC_FILTER:
		//	protoStr = "IPV6_MAX_SOCK_SRC_FILTER"

	}
	return protoStr
}
func EthProtoString(proto int) string {
	// ether proto definitions:
	// https://sites.uclouvain.be/SystInfo/usr/include/linux/if_ether.h.html
	// IEEE 802 Numbers https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
	protoStr := fmt.Sprintf("UNKNOWN#%d", proto)
	switch proto {
	case syscall.ETH_P_ALL:
		protoStr = "ALL"
	case syscall.ETH_P_IP: // Ox0800
		protoStr = "IP"
	case syscall.ETH_P_ARP:
		protoStr = "ARP"
	case syscall.ETH_P_RARP:
		protoStr = "RARP"
	case syscall.ETH_P_IPV6:
		protoStr = "IPV6"
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

	//log.Printf("%-15s %-6s -> %-15s %-6s %-6s",
	//	"interface",
	//	"protocol",
	//	"src",
	//	"->",
	//	"dst",
	//)
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

		// filter
		if ProtoString(int(event.IpProto)) == "TCP" {
			continue
		}

		log.Printf(
			"%-2d%-6s %-4s %-4s %-8s "+
				"| %-6s > %-6s "+
				"| %-13s "+
				"| %-13s > %-13s "+
				"| %-5d > %-5d",
			event.Ifindex,
			LookupName(int(event.Ifindex)),
			EthProtoString(int(htons(uint16(event.EthProto)))),
			ProtoString(int(event.IpProto)),
			pktTypeString(int(event.PktType)),

			macToLowerCaseString(event.SrcMac),
			macToLowerCaseString(event.DstMac),

			//intToIP(event.Nexthop),
			Mac2Ip(macToLowerCaseString(event.DstMac)),

			intToIP(event.SrcAddr),
			intToIP(event.DstAddr),

			event.Port16[0],
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

func pktTypeString(pktType int) string {
	// pkttype definitions:
	// https://github.com/torvalds/linux/blob/v5.14-rc7/include/uapi/linux/if_packet.h#L26
	pktTypeNames := []string{
		"HOST",
		"BROADCAST",
		"MULTICAST",
		"OTHERHOST",
		"OUTGOING",
		"LOOPBACK",
		"USER",
		"KERNEL",
	}
	pktTypeStr := fmt.Sprintf("UNKNOWN#%d", pktType)
	if uint(pktType) < uint(len(pktTypeNames)) {
		pktTypeStr = pktTypeNames[pktType]
	}
	return pktTypeStr
}

func macToUpperCaseString(mac [6]uint8) string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func macToLowerCaseString(mac [6]uint8) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func Mac2Ip(macAddress string) string {
	ip, err := findIPByMAC(macAddress)
	if err != nil {
		ipLocal, err := IfaceMacToIP(macAddress)
		if err != nil {
			return "0.0.0.0"
		} else {
			return ipLocal
		}

	} else {
		return ip
	}
}

func findIPByMAC(macAddress string) (string, error) {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 6 && fields[3] == macAddress {
			return fields[0], nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("MAC address not found in ARP table")
}

func IfaceMacToIP(mac string) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		// 获取接口的硬件地址（MAC 地址）
		hwAddr := iface.HardwareAddr.String()
		//fmt.Println(hwAddr)
		if hwAddr == mac {
			addrs, err := iface.Addrs()
			if err != nil {
				return "", err
			}

			// 通常情况下，一个接口可能有多个 IP 地址，这里只返回第一个
			if len(addrs) > 0 {
				ip, _, err := net.ParseCIDR(addrs[0].String())
				if err != nil {
					return "", err
				}
				return ip.String(), nil
			}
		}
	}

	return "", fmt.Errorf("MAC address not found in iface")
}
