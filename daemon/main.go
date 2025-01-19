package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

type HttpEvent struct {
	SrcIP   uint32
	DstIP   uint32
	DstPort uint16
	Data    [64]byte
}

type BPFObjects struct {
	HttpEvents *ebpf.Map     `ebpf:"http_events"`
	Prog       *ebpf.Program `ebpf:"http_filter"`
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpec("ebpf/http.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF object: %v", err)
	}

	var objs BPFObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.HttpEvents.Close()
	defer objs.Prog.Close()

	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Fatalf("Failed to create raw socket: %v", err)
	}
	defer syscall.Close(sock)

	iface, err := net.InterfaceByName("ens33")
	if err != nil {
		log.Fatalf("Failed to get interface: %v", err)
	}

	addr := syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: iface.Index}
	if err := syscall.Bind(sock, &addr); err != nil {
		log.Fatalf("Failed to bind socket: %v", err)
	}

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, objs.Prog.FD()); err != nil {
		log.Fatalf("Failed to attach BPF program to socket: %v", err)
	}

	reader, err := perf.NewReader(objs.HttpEvents, 4096)
	if err != nil {
		log.Fatalf("Failed to create perf event reader: %v", err)
	}
	defer reader.Close()

	fmt.Println("Listening for HTTP requests...")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				log.Printf("Error reading from perf buffer: %v", err)
				continue
			}

			var event HttpEvent
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				log.Printf("Failed to parse event: %v", err)
				continue
			}

			httpData := bytes.Trim(event.Data[:], "\x00")
			fmt.Printf("HTTP Request from %s, to %s, port: %d, pay load: %s\n", u32ToIPv4(ntoh(event.SrcIP)), u32ToIPv4(ntoh(event.DstIP)), ntohs(event.DstPort), httpData)
		}
	}()

	<-sigChan
	fmt.Println("Exiting...")
	if err := unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_DETACH_BPF, 0); err != nil {
		log.Fatalf("Failed to detach BPF program: %v", err)
	}
	fmt.Println("Detached eBPF program.")
	fmt.Println("Exited")
}

var HostOrder = nativeEndian()

func nativeEndian() binary.ByteOrder {
	var i uint32 = 0x01020304
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)

	if b[0] == 0x04 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

func htons(h uint16) uint16 {
	b := make([]byte, 4)
	HostOrder.PutUint16(b, h)
	return binary.BigEndian.Uint16(b)
}

func ntohs(n uint16) uint16 {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b, n)
	return HostOrder.Uint16(b)
}

func ntoh(n uint32) uint32 {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return HostOrder.Uint32(b)
}

func u32ToIPv4(ip uint32) string {
	return net.IPv4(
		byte(ip>>24),
		byte(ip>>16),
		byte(ip>>8),
		byte(ip),
	).String()
}
