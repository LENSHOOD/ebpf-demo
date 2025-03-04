package ebpf_receiver

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

type Kind int

const (
	NodeSrc Kind = iota
	NodeDest
	Body
)
const Timestamp = "timestamp"
const DirectionKey = "direction"
const SrcSpanName = "tcp_event_src"
const DestSpanName = "tcp_event_dest"
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

const HttpMethod = "Method"
const HttpUri = "URI"
const HttpVersion = "Version"
const HttpStatus = "Status"
const BodyContent = "Content"

func generateEbpfTraces(l4Event *L4Event) ptrace.Traces {
	traces := ptrace.NewTraces()
	traceId := NewTraceID()

	srcRsSpan := traces.ResourceSpans().AppendEmpty()
	srcRs := srcRsSpan.Resource()
	fillResourceWithAttributes(&srcRs, l4Event, NodeSrc)
	srcScope := appendScopeSpans(&srcRsSpan)
	appendTraceSpans(&srcScope, traceId, SrcSpanName)

	destRsSpan := traces.ResourceSpans().AppendEmpty()
	destRs := destRsSpan.Resource()
	fillResourceWithAttributes(&destRs, l4Event, NodeDest)
	destScope := appendScopeSpans(&destRsSpan)
	appendTraceSpans(&destScope, traceId, DestSpanName)

	bodyRsSpan := traces.ResourceSpans().AppendEmpty()
	bodyRs := bodyRsSpan.Resource()
	fillResourceWithAttributes(&bodyRs, l4Event, Body)
	bodyScope := appendScopeSpans(&bodyRsSpan)
	appendTraceSpans(&bodyScope, traceId, BodySpanName)

	return traces
}

func fillResourceWithAttributes(resource *pcommon.Resource, event *L4Event, direction Kind) {
	attrs := resource.Attributes()
	attrs.PutInt(Timestamp, int64(event.TimestampNs))
	attrs.PutInt(DirectionKey, int64(direction))
	attrs.PutStr(ServiceName, "ebpf-receiver")
	switch direction {
	case NodeSrc:
		attrs.PutStr(MetadataIp, u32ToIPv4(ntoh(event.SrcIP)))
	case NodeDest:
		attrs.PutStr(MetadataIp, u32ToIPv4(ntoh(event.DstIP)))
	case Body:
		endOfData := int(event.DataLength)
		if endOfData > len(event.Data) {
			endOfData = len(event.Data)
		}
		data := event.Data[:endOfData]
		attrs.PutStr(BodyContent, string(data))
		attrs.PutInt(MetadataTrafficIdentifier, buildTrafficIdentifier(event))
		attrs.PutStr(MetadataSrc, u32ToIPv4(ntoh(event.SrcIP)))
		attrs.PutStr(MetadataDest, u32ToIPv4(ntoh(event.DstIP)))
		attrs.PutInt(MetadataSrcPort, int64(ntohs(event.SrcPort)))
		attrs.PutInt(MetadataDestPort, int64(ntohs(event.DstPort)))

		switch event.Protocol {
		case unix.IPPROTO_TCP:
			attrs.PutInt(TrafficType, int64(TCP))
			tryHttp(data, attrs)
		case unix.IPPROTO_UDP:
			attrs.PutInt(TrafficType, int64(UDP))
			if ntohs(event.SrcPort) == 53 || ntohs(event.DstPort) == 53 {
				tryDNS(data, attrs)
			}
		}

	}
}

func tryHttp(data []byte, attrs pcommon.Map) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	if !scanner.Scan() {
		return
	}

	firstLine := scanner.Text()
	parts := strings.Fields(firstLine)
	if len(parts) < 3 {
		return
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
}

func tryDNS(data []byte, attrs pcommon.Map) {
	var msg dnsmessage.Message
	_ = msg.Unpack(data)

	fmt.Printf("DNS: %s\n", msg.GoString())
	if !msg.Header.Response {
		attrs.PutInt(TrafficType, int64(DNS_REQ))
	} else {
		attrs.PutInt(TrafficType, int64(DNS_RESP))
	}
	attrs.PutStr(BodyContent, msg.GoString())
}

func buildTrafficIdentifier(event *L4Event) int64 {
	minIP, minPort, maxIP, maxPort := ntoh(event.SrcIP), ntohs(event.SrcPort), ntoh(event.DstIP), ntohs(event.DstPort)
	if minIP > maxIP {
		minIP, maxIP = maxIP, minIP
	}

	if minPort > maxPort {
		minPort, maxPort = maxPort, minPort
	}

	return int64(minIP)<<48 | int64(minPort)<<32 | int64(maxIP)<<16 | int64(maxPort)
}

func appendScopeSpans(resourceSpans *ptrace.ResourceSpans) ptrace.ScopeSpans {
	scopeSpans := resourceSpans.ScopeSpans().AppendEmpty()
	scopeSpans.Scope().SetName("ebpf-receiver")
	scopeSpans.Scope().SetVersion("1.0.0")
	return scopeSpans
}

func NewTraceID() pcommon.TraceID {
	return pcommon.TraceID(uuid.New())
}

func NewSpanID() pcommon.SpanID {
	var rngSeed int64
	_ = binary.Read(crand.Reader, binary.LittleEndian, &rngSeed)
	randSource := rand.New(rand.NewSource(rngSeed))

	var sid [8]byte
	randSource.Read(sid[:])
	spanID := pcommon.SpanID(sid)

	return spanID
}

func appendTraceSpans(scopeSpans *ptrace.ScopeSpans, traceId pcommon.TraceID, spanName string) {
	span := scopeSpans.Spans().AppendEmpty()
	span.SetTraceID(traceId)
	span.SetParentSpanID(pcommon.NewSpanIDEmpty())
	span.SetSpanID(NewSpanID())
	span.SetName(spanName)
	span.SetKind(ptrace.SpanKindClient)
	span.Status().SetCode(ptrace.StatusCodeOk)
	span.SetStartTimestamp(pcommon.Timestamp(time.Now().UnixNano()))
	span.SetEndTimestamp(pcommon.Timestamp(time.Now().UnixNano() + 1_000_000))
	span.Attributes().PutStr(ServiceName, "ebpf-receiver")
	span.Events().AppendEmpty()
	span.Links().AppendEmpty()
}
