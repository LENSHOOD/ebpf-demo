package ebpf_receiver

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"regexp"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"golang.org/x/sys/unix"
)

type QuadTuple struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
}

type Header struct {
	MonoTimestampNs uint64
	Protocol        uint32
	QuadTuple
	DataLength uint16
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
	Protocol uint16
	Family   uint16
	QuadTuple
}

type EqtpObjects struct {
	RB  *ebpf.Map     `ebpf:"qtp_events_rb"`
	Tcp *ebpf.Program `ebpf:"handle_tcp_connect"`
	Udp *ebpf.Program `ebpf:"handle_udp_sendmsg"`
}

type EbpfQuadTuplePid struct {
	objs        *EqtpObjects
	tcp_kp      link.Link
	udp_kp      link.Link
	eventReader *ringbuf.Reader
	pidMap      sync.Map
}

type FileRwEvent struct {
	Pid      uint32
	Comm     [16]byte
	Filename [256]byte
	Op       uint32
}

type FileRwObjects struct {
	RB *ebpf.Map     `ebpf:"frw_events_rb"`
	R  *ebpf.Program `ebpf:"handle_vfs_read_ret"`
	W  *ebpf.Program `ebpf:"handle_vfs_write_ret"`
}

type EbpfFileRw struct {
	objs        *FileRwObjects
	r_kp        link.Link
	w_kp        link.Link
	eventReader *ringbuf.Reader
}

type ebpfReceiver struct {
	host         component.Host
	cancel       context.CancelFunc
	nextConsumer consumer.Traces
	config       *EbpfRcvrConfig
	esf          *EbpfSocketFilter
	eqtp         *EbpfQuadTuplePid
	efrw         *EbpfFileRw
}

func (rcvr *ebpfReceiver) Start(ctx context.Context, host component.Host) error {
	rcvr.host = host
	ctx, rcvr.cancel = context.WithCancel(ctx)

	rcvr.loadQuadTuplePid(rcvr.config.EbpfPidBinPath)
	rcvr.loadFileRw(rcvr.config.EbpfFileRwBinPath)
	rcvr.loadSocketFilter(rcvr.config.EbpfTrafficBinPath, rcvr.config.NicName)

	Logger().Sugar().Info("Listening for L4 traffic...")

	go rcvr.listenPid(ctx)()
	go rcvr.listenFileRw(ctx)()
	go rcvr.listenTraffic(ctx)()

	return nil
}

func (rcvr *ebpfReceiver) loadQuadTuplePid(binPath string) {
	loadEbpf(binPath, rcvr.eqtp.objs)

	tcp_kp, err := link.Kprobe("tcp_connect", rcvr.eqtp.objs.Tcp, nil)
	if err != nil {
		Logger().Sugar().Fatalf("Failed to tcp handler: %v", err)
	}
	rcvr.eqtp.tcp_kp = tcp_kp

	udp_kp, err := link.Kprobe("udp_sendmsg", rcvr.eqtp.objs.Udp, nil)
	if err != nil {
		Logger().Sugar().Fatalf("Failed to udp handler: %v", err)
	}
	rcvr.eqtp.udp_kp = udp_kp

	reader, err := ringbuf.NewReader(rcvr.eqtp.objs.RB)
	if err != nil {
		Logger().Sugar().Fatalf("Failed to create event reader: %v", err)
	}
	rcvr.eqtp.eventReader = reader
}

func (rcvr *ebpfReceiver) loadFileRw(binPath string) {
	loadEbpf(binPath, rcvr.efrw.objs)

	r_kp, err := link.Kprobe("vfs_read", rcvr.efrw.objs.R, nil)
	if err != nil {
		Logger().Sugar().Fatalf("Failed to vfs_read: %v", err)
	}
	rcvr.efrw.r_kp = r_kp

	w_kp, err := link.Kprobe("vfs_write", rcvr.efrw.objs.W, nil)
	if err != nil {
		Logger().Sugar().Fatalf("Failed to vfs_write: %v", err)
	}
	rcvr.efrw.w_kp = w_kp

	reader, err := ringbuf.NewReader(rcvr.efrw.objs.RB)
	if err != nil {
		Logger().Sugar().Fatalf("Failed to create event reader: %v", err)
	}
	rcvr.efrw.eventReader = reader
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
	go rcvr.eqtp.clear(2 * time.Minute)

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
					if err := binary.Read(buf, binary.BigEndian, &event); err != nil {
						if err != io.EOF {
							Logger().Sugar().Errorf("Failed to parse event header: %v", err)
						}
						continue
					}

					Logger().Sugar().Debugf("Pid %d: from %s:%d, to %s:%d, protocal: %d\n",
						event.Pid,
						u32ToIPv4(event.SrcIP),
						event.SrcPort,
						u32ToIPv4(event.DstIP),
						event.DstPort,
						event.Protocol)

					rcvr.eqtp.SetPid(event.QuadTuple.SrcIP, event.Pid)
				}
			}
		}
	}
}

func (rcvr *ebpfReceiver) listenFileRw(ctx context.Context) func() {
	return func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				{
					record, err := rcvr.efrw.eventReader.Read()
					if err != nil {
						Logger().Sugar().Errorf("Error reading from perf buffer: %v", err)
						continue
					}

					var event FileRwEvent
					buf := bytes.NewBuffer(record.RawSample)
					if err := binary.Read(buf, binary.LittleEndian, &event); err != nil {
						if err != io.EOF {
							Logger().Sugar().Errorf("Failed to parse event header: %v", err)
						}
						continue
					}

					Logger().Sugar().Errorf("\n------------\nFileRW: %s: %s\n------------\n", string(event.Comm[:]), string(event.Filename[:]))
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
					if err := binary.Read(buf, binary.BigEndian, &event.Header); err != nil {
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
						u32ToIPv4(event.Header.SrcIP),
						event.Header.SrcPort,
						u32ToIPv4(event.Header.DstIP),
						event.Header.DstPort,
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

	ip := u32ToIPv4(event.Header.SrcIP)
	re := regexp.MustCompile(filter)
	return re.MatchString(ip)
}

type timedPid struct {
	pid uint32
	ts  time.Time
}

func (eqtp *EbpfQuadTuplePid) SetPid(ip uint32, pid uint32) {
	val := timedPid{
		pid,
		time.Now(),
	}
	eqtp.pidMap.Store(ip, val)
}

func (eqtp *EbpfQuadTuplePid) GetPid(ip uint32) uint32 {
	if val, ok := eqtp.pidMap.Load(ip); ok {
		tp, _ := val.(timedPid)
		return tp.pid
	}

	return 0
}

func (eqtp *EbpfQuadTuplePid) clear(ttl time.Duration) {
	ticker := time.NewTicker(ttl)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		eqtp.pidMap.Range(func(key, value any) bool {
			tp, _ := value.(timedPid)
			if now.Sub(tp.ts) > ttl {
				eqtp.pidMap.Delete(key)
			}
			return true
		})
	}
}

func (eqtp *EbpfQuadTuplePid) shutdown() {
	_ = eqtp.eventReader.Close()

	Logger().Sugar().Info("Detached eBPF program.")
	_ = eqtp.tcp_kp.Close()
	_ = eqtp.udp_kp.Close()

	_ = eqtp.objs.RB.Close()
	_ = eqtp.objs.Tcp.Close()
	_ = eqtp.objs.Udp.Close()
}

func (efrw *EbpfFileRw) shutdown() {
	_ = efrw.eventReader.Close()

	Logger().Sugar().Info("Detached eBPF program.")
	_ = efrw.r_kp.Close()
	_ = efrw.w_kp.Close()

	_ = efrw.objs.RB.Close()
	_ = efrw.objs.R.Close()
	_ = efrw.objs.W.Close()
}

func (esf *EbpfSocketFilter) shutdown(isPromosc bool) {
	_ = esf.eventReader.Close()
	if err := unix.SetsockoptInt(esf.sockFd, unix.SOL_SOCKET, unix.SO_DETACH_BPF, 0); err != nil {
		Logger().Sugar().Fatalf("Failed to detach BPF program: %v", err)
	}

	if isPromosc {
		if err := unix.SetsockoptPacketMreq(esf.sockFd, unix.SOL_PACKET, unix.PACKET_DROP_MEMBERSHIP, &esf.mreq); err != nil {
			Logger().Sugar().Fatalf("Failed to set promisc: %v", err)
		}
	}

	_ = syscall.Close(esf.sockFd)
	Logger().Sugar().Info("Detached eBPF program.")
	_ = esf.objs.Rb.Close()
	_ = esf.objs.Prog.Close()
}

func (rcvr *ebpfReceiver) Shutdown(ctx context.Context) error {
	if rcvr.cancel != nil {
		rcvr.cancel()
	}

	Logger().Sugar().Info("Exiting...")
	rcvr.eqtp.shutdown()
	rcvr.efrw.shutdown()
	rcvr.esf.shutdown(rcvr.config.PromiscMode)
	Logger().Sugar().Info("Exited")

	return nil
}

var HostOrder = nativeEndian()

func nativeEndian() binary.ByteOrder {
	var i uint32 = 0x01020304
	b := (*[4]byte)(unsafe.Pointer(&i))

	if b[0] == 0x04 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

func htons(h uint16) uint16 {
	if HostOrder == binary.BigEndian {
		return h
	}

	return (h&0xFF)<<8 | (h&0xFF00)>>8
}

func u32ToIPv4(ip uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ip)
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}
