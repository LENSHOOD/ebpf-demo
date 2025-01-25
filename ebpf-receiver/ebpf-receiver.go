package ebpf_receiver

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
	"net"
	"syscall"
)

type TcpEvent struct {
	SrcIP   uint32
	DstIP   uint32
	DstPort uint16
	Data    [64]byte
}

type BPFObjects struct {
	TcpEvents *ebpf.Map     `ebpf:"tcp_events"`
	Prog      *ebpf.Program `ebpf:"net_filter"`
}

type ebpfReceiver struct {
	host         component.Host
	cancel       context.CancelFunc
	logger       *zap.Logger
	nextConsumer consumer.Traces
	config       *EbpfRcvrConfig
	objs         *BPFObjects
	sockFd       int
	eventReader  *perf.Reader
}

func (rcvr *ebpfReceiver) Start(ctx context.Context, host component.Host) error {
	rcvr.host = host
	ctx = context.Background()
	ctx, rcvr.cancel = context.WithCancel(ctx)

	rcvr.loadEbpfProgram(rcvr.config.EbpfBinPath, rcvr.config.NicName)

	rcvr.logger.Sugar().Info("Listening for TCP traffic...")

	go rcvr.listen(ctx)()

	return nil
}

func (rcvr *ebpfReceiver) loadEbpfProgram(binPath string, nicName string) {
	if err := rlimit.RemoveMemlock(); err != nil {
		rcvr.logger.Sugar().Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpec(binPath)
	if err != nil {
		rcvr.logger.Sugar().Fatal("Failed to load eBPF object: %v", err)
	}

	if err := spec.LoadAndAssign(rcvr.objs, nil); err != nil {
		rcvr.logger.Sugar().Fatal("Failed to load eBPF objects: %v", err)
	}

	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		rcvr.logger.Sugar().Fatal("Failed to create raw socket: %v", err)
	}
	rcvr.sockFd = sock

	iface, err := net.InterfaceByName(nicName)
	if err != nil {
		rcvr.logger.Sugar().Fatal("Failed to get interface: %v", err)
	}

	addr := syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: iface.Index}
	if err := syscall.Bind(sock, &addr); err != nil {
		rcvr.logger.Sugar().Fatal("Failed to bind socket: %v", err)
	}

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, rcvr.objs.Prog.FD()); err != nil {
		rcvr.logger.Sugar().Fatal("Failed to attach BPF program to socket: %v", err)
	}

	reader, err := perf.NewReader(rcvr.objs.TcpEvents, 4096)
	if err != nil {
		rcvr.logger.Sugar().Fatal("Failed to create perf event reader: %v", err)
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
						rcvr.logger.Sugar().Info("Error reading from perf buffer: %v", err)
						continue
					}

					var event TcpEvent
					err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
					if err != nil {
						rcvr.logger.Sugar().Info("Failed to parse event: %v", err)
						continue
					}

					httpData := bytes.Trim(event.Data[:], "\x00")
					rcvr.logger.Sugar().Debugf("TCP Packaet: from %s, to %s, port: %d, pay load: %v\n", u32ToIPv4(ntoh(event.SrcIP)), u32ToIPv4(ntoh(event.DstIP)), ntohs(event.DstPort), httpData)
					_ = rcvr.nextConsumer.ConsumeTraces(ctx, generateEbpfTraces(&event))
				}
			}
		}
	}
}

func (rcvr *ebpfReceiver) Shutdown(ctx context.Context) error {
	if rcvr.cancel != nil {
		rcvr.cancel()
	}

	rcvr.logger.Sugar().Info("Exiting...")
	_ = rcvr.eventReader.Close()
	if err := unix.SetsockoptInt(rcvr.sockFd, unix.SOL_SOCKET, unix.SO_DETACH_BPF, 0); err != nil {
		rcvr.logger.Sugar().Fatal("Failed to detach BPF program: %v", err)
	}
	_ = syscall.Close(rcvr.sockFd)
	rcvr.logger.Sugar().Info("Detached eBPF program.")
	_ = rcvr.objs.TcpEvents.Close()
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
