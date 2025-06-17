package ebpf_receiver

import (
	"sync"
	"testing"
)

func TestEbpfQuadTuplePid_SetPid(t *testing.T) {

	type args struct {
		qt_set  QuadTuple
		qt_get  QuadTuple
		pid uint32
		found bool
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "the same tuple can be found",
			args: args{
				qt_set: QuadTuple{
					SrcIP:   170524896,
					DstIP:   170590218,
					SrcPort: 53,
					DstPort: 38750,
				},
				qt_get: QuadTuple{
					SrcIP:   170524896,
					DstIP:   170590218,
					SrcPort: 53,
					DstPort: 38750,
				},
				pid: 1234,
				found: true,
			},
		},
		{
			name: "the different tuple cannot be found",
			args: args{
				qt_set: QuadTuple{
					SrcIP:   170524896,
					DstIP:   170590218,
					SrcPort: 53,
					DstPort: 38750,
				},
				qt_get: QuadTuple{
					SrcIP:   170524847,
					DstIP:   170590218,
					SrcPort: 8080,
					DstPort: 1234,
				},
				pid: 1234,
				found: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eqtp := &EbpfQuadTuplePid{
				pidMap: sync.Map{},
			}

			eqtp.SetPid(tt.args.qt_set.SrcIP, tt.args.pid)

			pid := eqtp.GetPid(tt.args.qt_get.SrcIP)

			if tt.args.found && pid != tt.args.pid{
				t.Fatalf("test failed")
			}

			if !tt.args.found && pid != 0 {
				t.Fatalf("test failed")
			}
		})
	}
}
