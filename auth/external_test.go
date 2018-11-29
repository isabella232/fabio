package auth

import (
	"reflect"
	"testing"
)

func TestExternal_SupportedProto(t *testing.T) {
	externalAuth := external{}

	tests := []struct {
		name string
		out  bool
	}{
		{
			"http",
			true,
		},
		{
			"https",
			true,
		},
		{
			"grpc",
			true,
		},
		{
			"grpcs",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, want := externalAuth.SupportedProto(tt.name), tt.out; !reflect.DeepEqual(got, want) {
				t.Errorf("got %v want %v", got, want)
			}
		})
	}
}
