package ebpf_receiver

import (
	crand "crypto/rand"
	"encoding/binary"
	"github.com/google/uuid"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"math/rand"
)

func generateEbpfTraces(tcpEvent *TcpEvent) ptrace.Traces {
	traces := ptrace.NewTraces()
	resourceSpan := traces.ResourceSpans().AppendEmpty()
	tcpResource := resourceSpan.Resource()
	fillResourceWithAttributes(&tcpResource, tcpEvent)

	scope := appendScopeSpans(&resourceSpan)
	appendTraceSpans(&scope)

	return traces
}

func fillResourceWithAttributes(resource *pcommon.Resource, event *TcpEvent) {
	attrs := resource.Attributes()
	// Here we set the "k8s.pod.ip" to be the same as the SrcIP, which helps the subsequent k8s processor in associating
	// Pod metadata. The SrcIP is sufficient for associating all Pod's metadata, as both sides of Tcp packets are sniffed,
	// regardless of whether a Pod is at the source or destination, all of them can be accounted at last.
	attrs.PutStr("k8s.pod.ip", u32ToIPv4(ntoh(event.SrcIP)))
	attrs.PutStr("src.ip", u32ToIPv4(ntoh(event.SrcIP)))
	attrs.PutStr("dest.ip", u32ToIPv4(ntoh(event.DstIP)))
	attrs.PutInt("dest.port", int64(ntohs(event.DstPort)))
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

func appendTraceSpans(scopeSpans *ptrace.ScopeSpans) {
	span := scopeSpans.Spans().AppendEmpty()
	span.SetTraceID(NewTraceID())
	span.SetSpanID(NewSpanID())
	span.SetName("tcp_event_span")
	span.SetKind(ptrace.SpanKindClient)
	span.Status().SetCode(ptrace.StatusCodeOk)
}
