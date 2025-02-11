package ebpf_receiver

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"github.com/google/uuid"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"math/rand"
	"strings"
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

type TT int

const (
	UNKNOWN = iota
	HTTP_REQ
	HTTP_RESP
)

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

func generateEbpfTraces(tcpEvent *TcpEvent) ptrace.Traces {
	traces := ptrace.NewTraces()
	traceId := NewTraceID()

	srcRsSpan := traces.ResourceSpans().AppendEmpty()
	srcRs := srcRsSpan.Resource()
	fillResourceWithAttributes(&srcRs, tcpEvent, NodeSrc)
	srcScope := appendScopeSpans(&srcRsSpan)
	appendTraceSpans(&srcScope, traceId, SrcSpanName)

	destRsSpan := traces.ResourceSpans().AppendEmpty()
	destRs := destRsSpan.Resource()
	fillResourceWithAttributes(&destRs, tcpEvent, NodeDest)
	destScope := appendScopeSpans(&destRsSpan)
	appendTraceSpans(&destScope, traceId, DestSpanName)

	bodyRsSpan := traces.ResourceSpans().AppendEmpty()
	bodyRs := bodyRsSpan.Resource()
	fillResourceWithAttributes(&bodyRs, tcpEvent, Body)
	bodyScope := appendScopeSpans(&bodyRsSpan)
	appendTraceSpans(&bodyScope, traceId, BodySpanName)

	return traces
}

func fillResourceWithAttributes(resource *pcommon.Resource, event *TcpEvent, direction Kind) {
	attrs := resource.Attributes()
	attrs.PutInt(Timestamp, int64(event.TimestampNs))
	attrs.PutInt(DirectionKey, int64(direction))
	switch direction {
	case NodeSrc:
		attrs.PutStr(MetadataIp, u32ToIPv4(ntoh(event.SrcIP)))
	case NodeDest:
		attrs.PutStr(MetadataIp, u32ToIPv4(ntoh(event.DstIP)))
	case Body:
		data := event.Data[:]
		attrs.PutStr(BodyContent, string(data))
		attrs.PutStr(MetadataSrc, u32ToIPv4(ntoh(event.SrcIP)))
		attrs.PutStr(MetadataDest, u32ToIPv4(ntoh(event.DstIP)))
		attrs.PutInt(MetadataSrcPort, int64(ntohs(event.SrcPort)))
		attrs.PutInt(MetadataDestPort, int64(ntohs(event.DstPort)))

		attrs.PutInt(TrafficType, UNKNOWN)
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
			attrs.PutInt(TrafficType, HTTP_RESP)
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
				attrs.PutInt(TrafficType, HTTP_REQ)
				attrs.PutStr(HttpMethod, firstSegment)
				attrs.PutStr(HttpUri, parts[1])
				attrs.PutStr(HttpVersion, parts[2])
			}
		}
	}
}

func appendScopeSpans(resourceSpans *ptrace.ResourceSpans) ptrace.ScopeSpans {
	scopeSpans := resourceSpans.ScopeSpans().AppendEmpty()

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
	span.SetSpanID(NewSpanID())
	span.SetName(spanName)
	span.SetKind(ptrace.SpanKindClient)
	span.Status().SetCode(ptrace.StatusCodeOk)
}
