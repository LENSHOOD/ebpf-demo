package ebpf_receiver

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"regexp"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

type L4Event struct {
	TimestampNs uint64
	Protocol    uint32
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	DataLength  uint16
	Data        [80]byte
}

type BPFObjects struct {
	Rb   *ebpf.Map     `ebpf:"l4_events_rb"`
	Prog *ebpf.Program `ebpf:"net_filter"`
}

type ebpfReceiver struct {
	host         component.Host
	cancel       context.CancelFunc
	logger       *zap.Logger
	nextConsumer consumer.Traces
	config       *EbpfRcvrConfig
	objs         *BPFObjects
	sockFd       int
	eventReader  *ringbuf.Reader
	mreq         unix.PacketMreq
}

func (rcvr *ebpfReceiver) Start(ctx context.Context, host component.Host) error {
	rcvr.host = host
	ctx = context.Background()
	ctx, rcvr.cancel = context.WithCancel(ctx)

	rcvr.loadEbpfProgram(rcvr.config.EbpfBinPath, rcvr.config.NicName)

	rcvr.logger.Sugar().Info("Listening for L4 traffic...")

	go rcvr.listen(ctx)()

	return nil
}

func (rcvr *ebpfReceiver) loadEbpfProgram(binPath string, nicName string) {
	if err := rlimit.RemoveMemlock(); err != nil {
		rcvr.logger.Sugar().Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpec(binPath)
	if err != nil {
		rcvr.logger.Sugar().Fatalf("Failed to load eBPF object: %v", err)
	}

	if err := spec.LoadAndAssign(rcvr.objs, nil); err != nil {
		rcvr.logger.Sugar().Fatalf("Failed to load eBPF objects: %v", err)
	}

	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		rcvr.logger.Sugar().Fatalf("Failed to create raw socket: %v", err)
	}
	rcvr.sockFd = sock

	iface, err := net.InterfaceByName(nicName)
	if err != nil {
		rcvr.logger.Sugar().Fatalf("Failed to get interface: %v", err)
	}

	addr := syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: iface.Index}
	if err := syscall.Bind(sock, &addr); err != nil {
		rcvr.logger.Sugar().Fatalf("Failed to bind socket: %v", err)
	}

	if rcvr.config.PromiscMode {
		rcvr.mreq = unix.PacketMreq{
			Ifindex: int32(iface.Index),
			Type:    unix.PACKET_MR_PROMISC,
		}
		if err := unix.SetsockoptPacketMreq(sock, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &rcvr.mreq); err != nil {
			rcvr.logger.Sugar().Fatalf("Failed to set promisc: %v", err)
		}
	}

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, rcvr.objs.Prog.FD()); err != nil {
		rcvr.logger.Sugar().Fatalf("Failed to attach BPF program to socket: %v", err)
	}

	reader, err := ringbuf.NewReader(rcvr.objs.Rb)
	if err != nil {
		rcvr.logger.Sugar().Fatalf("Failed to create perf event reader: %v", err)
	}
	rcvr.eventReader = reader
}

func (rcvr *ebpfReceiver) listen(ctx context.Context) func() {
	return func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				{
					record, err := rcvr.eventReader.Read()
					if err != nil {
						rcvr.logger.Sugar().Errorf("Error reading from perf buffer: %v", err)
						continue
					}

					var event L4Event
					err = binary.Read(bytes.NewBuffer(record.RawSample), HostOrder, &event)
					if err != nil {
						if err != io.EOF {
							rcvr.logger.Sugar().Errorf("Failed to parse event: %v", err)
						}
						continue
					}

					if !allows(rcvr.config.IpFilter, event) {
						continue
					}

					rcvr.logger.Sugar().Debugf("L4 Packaet: from %s:%d, to %s:%d, protocal: %d, len: %d\n", u32ToIPv4(ntoh(event.SrcIP)), ntohs(event.SrcPort), u32ToIPv4(ntoh(event.DstIP)), ntohs(event.DstPort), event.Protocol, event.DataLength)
					_ = rcvr.nextConsumer.ConsumeTraces(ctx, generateEbpfTraces(&event))
				}
			}
		}
	}
}

func allows(filter string, event L4Event) bool {
	if filter == "" {
		return true
	}

	ip := u32ToIPv4(ntoh(event.SrcIP))
	re := regexp.MustCompile(filter)
	return re.MatchString(ip)
}

func (rcvr *ebpfReceiver) Shutdown(ctx context.Context) error {
	if rcvr.cancel != nil {
		rcvr.cancel()
	}

	rcvr.logger.Sugar().Info("Exiting...")
	_ = rcvr.eventReader.Close()
	if err := unix.SetsockoptInt(rcvr.sockFd, unix.SOL_SOCKET, unix.SO_DETACH_BPF, 0); err != nil {
		rcvr.logger.Sugar().Fatalf("Failed to detach BPF program: %v", err)
	}

	if rcvr.config.PromiscMode {
		if err := unix.SetsockoptPacketMreq(rcvr.sockFd, unix.SOL_PACKET, unix.PACKET_DROP_MEMBERSHIP, &rcvr.mreq); err != nil {
			rcvr.logger.Sugar().Fatalf("Failed to set promisc: %v", err)
		}
	}

	_ = syscall.Close(rcvr.sockFd)
	rcvr.logger.Sugar().Info("Detached eBPF program.")
	_ = rcvr.objs.Rb.Close()
	_ = rcvr.objs.Prog.Close()
	rcvr.logger.Sugar().Info("Exited")

	return nil
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
