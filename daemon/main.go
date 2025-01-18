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
			fmt.Printf("HTTP Request from %d, to %d, pay load: %s\n", event.SrcIP, event.DstIP, httpData)
		}
	}()

	<-sigChan
	fmt.Println("Exiting...")
}

func htons(i uint16) uint16 {
	return (i<<8)&0xFF00 | (i>>8)&0x00FF
}
