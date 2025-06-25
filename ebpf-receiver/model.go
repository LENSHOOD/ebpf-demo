package ebpf_receiver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"

	"github.com/jackc/pgx/v5/pgproto3"
)

const BodySpanName = "tcp_event_body"
const TrafficType = "traffic.type"
const ServiceName = "service.name"

type TT int

const (
	TCP TT = iota
	UDP
	HTTP_REQ
	HTTP_RESP
	DNS_REQ
	DNS_RESP
	PGSQL_QUERY
	PGSQL_RESP
)

const MetadataTrafficIdentifier = "traffic.identifier"
const MetadataIp = "k8s.pod.ip"
const MetadataSrc = "src.ip"
const MetadataDest = "dest.ip"
const MetadataSrcPort = "src.port"
const MetadataDestPort = "dest.port"
const MetadataNS = "k8s.namespace.name"
const MetadataDeployName = "k8s.deployment.name"
const MetadataNodeName = "k8s.node.name"
const MetadataPodName = "k8s.pod.name"
const MetaSrcPid = "src.pid"
const MetaDestPid = "dest.pid"

const HttpMethod = "Method"
const HttpUri = "URI"
const HttpVersion = "Version"
const HttpStatus = "Status"
const BodyContent = "Content"

const OtelTraceParent = "traceparent"
const OtelTraceState = "tracestate"

func (rcvr *ebpfReceiver) generateEbpfTraces(l4Event *L4Event) ptrace.Traces {
	bodyAttributes := rcvr.fillResourceWithAttributes(l4Event)

	trafficType := getInt(bodyAttributes, TrafficType)
	traceParent, traceState := "", ""
	if trafficType == int64(HTTP_REQ) || trafficType == int64(HTTP_RESP) {
		traceParent = getStr(bodyAttributes, OtelTraceParent)
		traceState = getStr(bodyAttributes, OtelTraceState)
	}

	traceId := NewTraceID()
	parentSpanId := pcommon.NewSpanIDEmpty()
	if traceParent != "" {
		var propagator = propagation.TraceContext{}
		carrier := propagation.HeaderCarrier{}
		carrier.Set("traceparent", traceParent)
		if traceState != "" {
			carrier.Set("tracestate", traceState)
		}
		ctx := propagator.Extract(context.Background(), carrier)
		parentSpanCtx := trace.SpanContextFromContext(ctx)
		traceId = pcommon.TraceID(parentSpanCtx.TraceID())
		parentSpanId = pcommon.SpanID(parentSpanCtx.SpanID())
		Logger().Sugar().Debugf("TraceParent: %s, TraceState: %s, TraceId: %s, ParentSpan: %s", traceParent, traceState, traceId.String(), parentSpanId.String())
	}

	trace, span, rs := getSpanWithRs(traceId, parentSpanId, "ebpf-net-traffic")
	bodyAttributes.CopyTo(rs.Attributes())

	ts := time.Now().UTC().UnixNano()
	span.SetStartTimestamp(pcommon.Timestamp(ts))
	span.SetEndTimestamp(pcommon.Timestamp(ts + 1_000_000))

	return trace
}

func (rcvr *ebpfReceiver) fillResourceWithAttributes(event *L4Event) *pcommon.Map {
	attrs := pcommon.NewMap()

	endOfData := int(event.Header.DataLength)
	if endOfData > len(event.Data) {
		endOfData = len(event.Data)
	}
	data := event.Data[:endOfData]
	attrs.PutStr(ServiceName, "ebpf-receiver")
	attrs.PutStr(BodyContent, string(data))
	attrs.PutInt(MetadataTrafficIdentifier, buildTrafficIdentifier(event))
	attrs.PutStr(MetadataSrc, u32ToIPv4(event.Header.SrcIP))
	attrs.PutStr(MetadataDest, u32ToIPv4(event.Header.DstIP))
	attrs.PutInt(MetadataSrcPort, int64(event.Header.SrcPort))
	attrs.PutInt(MetadataDestPort, int64(event.Header.DstPort))

	switch event.Header.Protocol {
	case unix.IPPROTO_TCP:
		attrs.PutInt(TrafficType, int64(TCP))
		if err := tryHttp11(data, &attrs); err != nil {
			_ = tryPgsql(data, &attrs)
		}
	case unix.IPPROTO_UDP:
		attrs.PutInt(TrafficType, int64(UDP))
		if event.Header.SrcPort == 53 || event.Header.DstPort == 53 {
			tryDNS(data, &attrs)
		}
	}

	src_pid := rcvr.eqtp.GetPid(event.Header.SrcIP)
	dest_pid := rcvr.eqtp.GetPid(event.Header.DstIP)
	attrs.PutInt(MetaSrcPid, int64(src_pid))
	attrs.PutInt(MetaDestPid, int64(dest_pid))

	return &attrs
}

func getSpanWithRs(traceId pcommon.TraceID, parentSpanId pcommon.SpanID, spanName string) (ptrace.Traces, ptrace.Span, pcommon.Resource) {
	traces := ptrace.NewTraces()
	ebpfSpan := traces.ResourceSpans().AppendEmpty()
	ebpfRs := ebpfSpan.Resource()
	scopeSpans := ebpfSpan.ScopeSpans().AppendEmpty()
	scopeSpans.Scope().SetName("ebpf-receiver")

	span := scopeSpans.Spans().AppendEmpty()
	span.SetTraceID(traceId)
	span.SetParentSpanID(parentSpanId)
	span.SetSpanID(NewSpanID())
	span.SetName(spanName)
	span.SetKind(ptrace.SpanKindClient)
	span.Status().SetCode(ptrace.StatusCodeOk)

	return traces, span, ebpfRs
}

func tryHttp11(data []byte, attrs *pcommon.Map) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))

	lineNum := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		Logger().Sugar().Debugf("HTTP RAW: %s", line)
		if lineNum == 0 {
			parts := strings.Fields(line)
			if len(parts) < 3 {
				return errors.New("parsing failed")
			}

			firstSegment := parts[0]
			if strings.HasPrefix(firstSegment, "HTTP") {
				attrs.PutInt(TrafficType, int64(HTTP_RESP))
				attrs.PutStr(HttpVersion, firstSegment)
				attrs.PutStr(HttpStatus, parts[1]+" "+parts[2])
			}

			if strings.HasPrefix(firstSegment, "GET") ||
				strings.HasPrefix(firstSegment, "POST") ||
				strings.HasPrefix(firstSegment, "PUT") ||
				strings.HasPrefix(firstSegment, "DELE") ||
				strings.HasPrefix(firstSegment, "HEAD") ||
				strings.HasPrefix(firstSegment, "OPTI") {
				{
					attrs.PutInt(TrafficType, int64(HTTP_REQ))
					attrs.PutStr(HttpMethod, firstSegment)
					attrs.PutStr(HttpUri, parts[1])
					attrs.PutStr(HttpVersion, parts[2])
				}
			}
		} else {
			colonIndex := strings.Index(line, ":")
			if colonIndex != -1 {
				key := strings.TrimSpace(line[:colonIndex])
				val := strings.TrimSpace(line[colonIndex+1:])
				if key == "traceparent" {
					attrs.PutStr("traceparent", val)
				}
				if key == "tracestate" {
					attrs.PutStr("tracestate", val)
				}
			}
		}
		lineNum++
	}

	t := getInt(attrs, TrafficType)
	if t != int64(HTTP_REQ) && t != int64(HTTP_RESP) {
		return errors.New("invalid http1.1 data")
	}
	return nil
}

func tryPgsql(data []byte, attrs *pcommon.Map) error {
	b := pgproto3.NewBackend(bytes.NewReader(data), nil)
	// this is very important beacuse some arbitrary data may happen to match the
	// pgsql type could lead to the Receive() allocating a very very big buffer on stack
	b.SetMaxBodyLen(len(data))
	var e error = nil
	hasQurey := false

	for {
		msg, err := b.Receive()
		if err != nil {
			if err != io.ErrUnexpectedEOF {
				e = err
			}
			break
		}
		switch pkt := msg.(type) {
		case *pgproto3.Query:
			attrs.PutInt(TrafficType, int64(PGSQL_QUERY))
			attrs.PutStr("Query", pkt.String)
			hasQurey = true
		case *pgproto3.Parse:
			attrs.PutInt(TrafficType, int64(PGSQL_QUERY))
			attrs.PutStr("Query", pkt.Query)
			hasQurey = true
		}
	}

	if hasQurey {
		return nil
	}

	return e
}

func tryDNS(data []byte, attrs *pcommon.Map) {
	var msg dnsmessage.Message
	_ = msg.Unpack(data)

	Logger().Sugar().Debugf("DNS: %s\n", msg.GoString())
	if !msg.Header.Response {
		attrs.PutInt(TrafficType, int64(DNS_REQ))
	} else {
		attrs.PutInt(TrafficType, int64(DNS_RESP))
	}
	attrs.PutStr(BodyContent, msg.GoString())
}

func (rcvr *ebpfReceiver) generateFilRwTrace(event *FileRwEvent, path string) ptrace.Traces {
	traceId := NewTraceID()
	parentSpanId := pcommon.NewSpanIDEmpty()

	trace, span, rs := getSpanWithRs(traceId, parentSpanId, "ebpf-file-rw")
	attr := rs.Attributes()
	attr.PutStr(ServiceName, "ebpf-receiver")
	attr.PutInt("PID", int64(event.Pid))
	attr.PutInt("FD", int64(event.Fd))
	op := "READ"
	if event.Op == 1 {
		op = "WRITE"
	}
	attr.PutStr("OP", op)
	attr.PutStr("CMD", string(event.Comm[:]))

	attr.PutStr("FILE_NAME", path)

	ts := time.Now().UTC().UnixNano()
	span.SetStartTimestamp(pcommon.Timestamp(ts))
	span.SetEndTimestamp(pcommon.Timestamp(ts + 1_000_000))

	return trace
}

func buildTrafficIdentifier(event *L4Event) int64 {
	minIP, minPort, maxIP, maxPort := event.Header.SrcIP, event.Header.SrcPort, event.Header.DstIP, event.Header.DstPort
	if minIP > maxIP {
		minIP, maxIP = maxIP, minIP
	}

	if minPort > maxPort {
		minPort, maxPort = maxPort, minPort
	}

	return int64(minIP)<<48 | int64(minPort)<<32 | int64(maxIP)<<16 | int64(maxPort)
}

func NewTraceID() pcommon.TraceID {
	var id [16]byte
	rand.Read(id[:])
	return pcommon.TraceID(id)
}

func NewSpanID() pcommon.SpanID {
	var id [8]byte
	rand.Read(id[:])
	return pcommon.SpanID(id)
}

func getInt(attr *pcommon.Map, key string) int64 {
	if v, exist := attr.Get(key); exist {
		return v.Int()
	}

	return -1
}

func getStr(attr *pcommon.Map, key string) string {
	if v, exist := attr.Get(key); exist {
		return v.Str()
	}

	return ""
}
