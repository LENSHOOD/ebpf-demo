package ebpf_receiver

import (
	crand "crypto/rand"
	"encoding/binary"
	"github.com/google/uuid"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"math/rand"
)

type Kind int

const (
	NODE_SRC Kind = iota
	NODE_DEST
	EDGE
)
const DirectionKey = "direction"
const SrcSpanName = "tcp_event_src"
const DestSpanName = "tcp_event_dest"
const MetadataIp = "k8s.pod.ip"
const MetadataSrc = "src.ip"
const MetadataDest = "dest.ip"
const MetadataPort = "port"
const MetadataNS = "k8s.namespace.name"
const MetadataDeployName = "k8s.deployment.name"
const MetadataNodeName = "k8s.node.name"
const MetadataPodName = "k8s.pod.name"

func generateEbpfTraces(tcpEvent *TcpEvent) ptrace.Traces {
	traces := ptrace.NewTraces()
	traceId := NewTraceID()

	srcRsSpan := traces.ResourceSpans().AppendEmpty()
	srcRs := srcRsSpan.Resource()
	fillResourceWithAttributes(&srcRs, tcpEvent, NODE_SRC)
	srcScope := appendScopeSpans(&srcRsSpan)
	appendTraceSpans(&srcScope, traceId, SrcSpanName)

	destRsSpan := traces.ResourceSpans().AppendEmpty()
	destRs := destRsSpan.Resource()
	fillResourceWithAttributes(&destRs, tcpEvent, NODE_DEST)
	destScope := appendScopeSpans(&destRsSpan)
	appendTraceSpans(&destScope, traceId, DestSpanName)

	edgeRsSpan := traces.ResourceSpans().AppendEmpty()
	edgeRs := edgeRsSpan.Resource()
	fillResourceWithAttributes(&edgeRs, tcpEvent, EDGE)
	edgeScope := appendScopeSpans(&edgeRsSpan)
	appendTraceSpans(&edgeScope, traceId, DestSpanName)

	return traces
}

func fillResourceWithAttributes(resource *pcommon.Resource, event *TcpEvent, direction Kind) {
	attrs := resource.Attributes()
	attrs.PutInt(DirectionKey, int64(direction))
	switch direction {
	case NODE_SRC:
		attrs.PutStr(MetadataIp, u32ToIPv4(ntoh(event.SrcIP)))
	case NODE_DEST:
		attrs.PutStr(MetadataIp, u32ToIPv4(ntoh(event.DstIP)))
		attrs.PutInt(MetadataPort, int64(ntohs(event.DstPort)))
	case EDGE:
		attrs.PutStr(MetadataSrc, u32ToIPv4(ntoh(event.SrcIP)))
		attrs.PutStr(MetadataDest, u32ToIPv4(ntoh(event.DstIP)))
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
