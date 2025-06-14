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
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"golang.org/x/sys/unix"
)

type Header struct {
	MonoTimestampNs uint64
	Protocol        uint32
	SrcIP           uint32
	DstIP           uint32
	SrcPort         uint16
	DstPort         uint16
	DataLength      uint16
}

type L4Event struct {
	Header Header
	Data   [1024]byte
}

type EsfObjects struct {
	Rb   *ebpf.Map     `ebpf:"l4_events_rb"`
	Prog *ebpf.Program `ebpf:"net_filter"`
}

type EbpfSocketFilter struct {
	objs        *EsfObjects
	sockFd      int
	eventReader *ringbuf.Reader
	mreq        unix.PacketMreq
}

type PidEvent struct {
	Pid      uint32
	Protocol uint8
	Family   uint8
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
}

type EqtpObjects struct {
	rb  *ebpf.Map     `ebpf:"qtp_events_rb"`
	tcp *ebpf.Program `ebpf:"handle_tcp_connect"`
	udp *ebpf.Program `ebpf:"handle_udp_sendmsg"`
}

type EbpfQuadTuplePid struct {
	objs        *EqtpObjects
	tcp_kp      link.Link
	udp_kp      link.Link
	eventReader *ringbuf.Reader
}

type ebpfReceiver struct {
	host         component.Host
	cancel       context.CancelFunc
	nextConsumer consumer.Traces
	config       *EbpfRcvrConfig
	esf          *EbpfSocketFilter
	eqtp         *EbpfQuadTuplePid
}

func (rcvr *ebpfReceiver) Start(ctx context.Context, host component.Host) error {
	rcvr.host = host
	ctx = context.Background()
	ctx, rcvr.cancel = context.WithCancel(ctx)

	rcvr.loadQuadTuplePid(rcvr.config.EbpfBinPath)
	rcvr.loadSocketFilter(rcvr.config.EbpfBinPath, rcvr.config.NicName)

	Logger().Sugar().Info("Listening for L4 traffic...")

	go rcvr.listenTraffic(ctx)()

	return nil
}

func (rcvr *ebpfReceiver) loadQuadTuplePid(binPath string) {
	loadEbpf(binPath, rcvr.eqtp.objs)

	tcp_kp, err := link.Kprobe("tcp_connect", rcvr.eqtp.objs.tcp, nil)
	if err != nil {
		Logger().Sugar().Fatalf("Failed to tcp handler: %v", err)
	}
	rcvr.eqtp.tcp_kp = tcp_kp

	udp_kp, err := link.Kprobe("udp_sendmsg", rcvr.eqtp.objs.udp, nil)
	if err != nil {
		Logger().Sugar().Fatalf("Failed to udp handler: %v", err)
	}
	rcvr.eqtp.udp_kp = udp_kp

	reader, err := ringbuf.NewReader(rcvr.eqtp.objs.rb)
	if err != nil {
		Logger().Sugar().Fatalf("Failed to create event reader: %v", err)
	}
	rcvr.eqtp.eventReader = reader
}

func (rcvr *ebpfReceiver) loadSocketFilter(binPath string, nicName string) {
	loadEbpf(binPath, rcvr.esf.objs)

	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		Logger().Sugar().Fatalf("Failed to create raw socket: %v", err)
	}
	rcvr.esf.sockFd = sock

	iface, err := net.InterfaceByName(nicName)
	if err != nil {
		Logger().Sugar().Fatalf("Failed to get interface: %v", err)
	}

	addr := syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: iface.Index}
	if err := syscall.Bind(sock, &addr); err != nil {
		Logger().Sugar().Fatalf("Failed to bind socket: %v", err)
	}

	if rcvr.config.PromiscMode {
		rcvr.esf.mreq = unix.PacketMreq{
			Ifindex: int32(iface.Index),
			Type:    unix.PACKET_MR_PROMISC,
		}
		if err := unix.SetsockoptPacketMreq(sock, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &rcvr.esf.mreq); err != nil {
			Logger().Sugar().Fatalf("Failed to set promisc: %v", err)
		}
	}

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, rcvr.esf.objs.Prog.FD()); err != nil {
		Logger().Sugar().Fatalf("Failed to attach BPF program to socket: %v", err)
	}

	reader, err := ringbuf.NewReader(rcvr.esf.objs.Rb)
	if err != nil {
		Logger().Sugar().Fatalf("Failed to create event reader: %v", err)
	}
	rcvr.esf.eventReader = reader
}

func (rcvr *ebpfReceiver) listenPid(ctx context.Context) func() {
	return func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				{
					record, err := rcvr.eqtp.eventReader.Read()
					if err != nil {
						Logger().Sugar().Errorf("Error reading from perf buffer: %v", err)
						continue
					}

					var event PidEvent
					buf := bytes.NewBuffer(record.RawSample)
					if err := binary.Read(buf, HostOrder, &event); err != nil {
						if err != io.EOF {
							Logger().Sugar().Errorf("Failed to parse event header: %v", err)
						}
						continue
					}
					
					// build map
				}
			}
		}
	}
}

func (rcvr *ebpfReceiver) listenTraffic(ctx context.Context) func() {
	return func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				{
					record, err := rcvr.esf.eventReader.Read()
					if err != nil {
						Logger().Sugar().Errorf("Error reading from perf buffer: %v", err)
						continue
					}

					var event L4Event
					buf := bytes.NewBuffer(record.RawSample)
					if err := binary.Read(buf, HostOrder, &event.Header); err != nil {
						if err != io.EOF {
							Logger().Sugar().Errorf("Failed to parse event header: %v", err)
						}
						continue
					}
					dataLen := int(event.Header.DataLength)
					if dataLen > len(event.Data) {
						dataLen = len(event.Data)
					}

					if _, err := buf.Read(event.Data[:dataLen]); err != nil {
						Logger().Sugar().Errorf("Failed to parse event data: %v", err)
						continue
					}

					if !allows(rcvr.config.IpFilter, event) {
						continue
					}

					Logger().Sugar().Debugf("L4 Packaet: from %s:%d, to %s:%d, protocal: %d, len: %d\n",
						u32ToIPv4(ntoh(event.Header.SrcIP)),
						ntohs(event.Header.SrcPort),
						u32ToIPv4(ntoh(event.Header.DstIP)),
						ntohs(event.Header.DstPort),
						event.Header.Protocol,
						event.Header.DataLength)

					_ = rcvr.nextConsumer.ConsumeTraces(ctx, rcvr.generateEbpfTraces(&event))
				}
			}
		}
	}
}

func loadEbpf(binPath string, objs any) {
	if err := rlimit.RemoveMemlock(); err != nil {
		Logger().Sugar().Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpec(binPath)
	if err != nil {
		Logger().Sugar().Fatalf("Failed to load eBPF object: %v", err)
	}

	if err := spec.LoadAndAssign(objs, nil); err != nil {
		Logger().Sugar().Fatalf("Failed to load eBPF objects: %v", err)
	}
}

func allows(filter string, event L4Event) bool {
	if filter == "" {
		return true
	}

	ip := u32ToIPv4(ntoh(event.Header.SrcIP))
	re := regexp.MustCompile(filter)
	return re.MatchString(ip)
}

func (rcvr *ebpfReceiver) Shutdown(ctx context.Context) error {
	if rcvr.cancel != nil {
		rcvr.cancel()
	}

	Logger().Sugar().Info("Exiting...")
	_ = rcvr.esf.eventReader.Close()
	if err := unix.SetsockoptInt(rcvr.esf.sockFd, unix.SOL_SOCKET, unix.SO_DETACH_BPF, 0); err != nil {
		Logger().Sugar().Fatalf("Failed to detach BPF program: %v", err)
	}

	if rcvr.config.PromiscMode {
		if err := unix.SetsockoptPacketMreq(rcvr.esf.sockFd, unix.SOL_PACKET, unix.PACKET_DROP_MEMBERSHIP, &rcvr.esf.mreq); err != nil {
			Logger().Sugar().Fatalf("Failed to set promisc: %v", err)
		}
	}

	_ = syscall.Close(rcvr.esf.sockFd)
	Logger().Sugar().Info("Detached eBPF program.")
	_ = rcvr.esf.objs.Rb.Close()
	_ = rcvr.esf.objs.Prog.Close()
	Logger().Sugar().Info("Exited")

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
