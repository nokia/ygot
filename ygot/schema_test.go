// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ygot

import (
	"reflect"
	"strings"
	"testing"

	json "github.com/openconfig/ygot/yjson"

	"github.com/openconfig/goyang/pkg/yang"
	"github.com/openconfig/ygot/testutil"
)

func TestGzipToSchema(t *testing.T) {
	rootElement := &yang.Entry{}
	containerElement := &yang.Entry{
		Name: "container",
		Annotation: map[string]interface{}{
			"schemapath": "/module/container",
			"structname": "container",
		},
		Parent: rootElement,
	}
	containerElement.Dir = map[string]*yang.Entry{
		"foo": {
			Name:   "foo",
			Parent: containerElement,
		},
	}
	rootElement.Dir = map[string]*yang.Entry{"container": containerElement}

	tests := []struct {
		name    string
		in      []byte
		want    map[string]*yang.Entry
		wantErr string
	}{{
		name: "simple entry",
		in: []byte{
			0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x90, 0xb1, 0xce, 0xc2, 0x30,
			0x0c, 0x84, 0xf7, 0x3e, 0x85, 0xe5, 0xb9, 0x52, 0xff, 0xb9, 0xdb, 0x2f, 0xd8, 0x90, 0x78, 0x87,
			0xa8, 0x4d, 0x69, 0x24, 0x62, 0xa3, 0xe2, 0x4e, 0x28, 0xef, 0x8e, 0x4a, 0x50, 0xc0, 0xa9, 0xd9,
			0xe2, 0xbb, 0x73, 0xee, 0x93, 0x1f, 0x0d, 0x00, 0x00, 0x9e, 0x5d, 0xf4, 0xd8, 0x03, 0x62, 0x9b,
			0xe7, 0x53, 0xa0, 0x11, 0x7b, 0xf8, 0x7b, 0x8f, 0x07, 0xa6, 0x29, 0x5c, 0xbe, 0x84, 0x63, 0x58,
			0xb0, 0x87, 0xbc, 0xfc, 0x12, 0x06, 0x26, 0x71, 0x81, 0xbc, 0x96, 0xd5, 0xdf, 0x9f, 0x48, 0xab,
			0x03, 0xba, 0xac, 0xc8, 0x75, 0x69, 0x31, 0xea, 0xf2, 0x62, 0x4c, 0xcc, 0xa6, 0xa1, 0x30, 0xb6,
			0x50, 0x6b, 0x47, 0x6c, 0x10, 0x03, 0x68, 0xe7, 0x27, 0xa5, 0xa4, 0x0a, 0xf8, 0x9f, 0x88, 0xc5,
			0x49, 0x60, 0xb2, 0xb9, 0xef, 0xc3, 0xec, 0xa3, 0xbb, 0x39, 0x99, 0x37, 0xc0, 0x2e, 0xf2, 0xb8,
			0x5e, 0x7d, 0xf7, 0xeb, 0x5e, 0x79, 0x45, 0x96, 0x75, 0x10, 0xda, 0x9d, 0xb6, 0xb1, 0xa9, 0xf2,
			0x2b, 0x35, 0xe9, 0x09, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0xff, 0xff, 0x03, 0x33, 0xd7,
			0x76, 0xf0, 0x01, 0x00, 0x00,
		},
		want: map[string]*yang.Entry{
			"container": containerElement,
		},
	}, {
		name:    "bad gzip data",
		in:      []byte("I am not a valid gzip!"),
		wantErr: "gzip: invalid header",
	}, {
		name: "bad JSON document",
		in: []byte{
			0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xaa, 0x56, 0xca, 0xcc, 0x2b, 0x4b,
			0xcc, 0xc9, 0x4c, 0xd1, 0xcd, 0x2a, 0xce, 0xcf, 0x53, 0xaa, 0x05, 0x00, 0x00, 0x00, 0xff, 0xff,
			0x01, 0x00, 0x00, 0xff, 0xff, 0x74, 0x4e, 0x31, 0xbb, 0x10, 0x00, 0x00, 0x00,
		},
		wantErr: "invalid character '}' after object key",
	}, {
		name:    "empty input",
		in:      []byte{},
		wantErr: "EOF",
	}}

	for _, tt := range tests {
		got, err := GzipToSchema(tt.in)
		if err != nil {
			if err.Error() != tt.wantErr {
				t.Errorf("%s: GzipToSchema(%v): got unexpected error, got: %v, want: %v\n", tt.name, tt.in, err, tt.wantErr)
			}
			continue
		}

		if !reflect.DeepEqual(got, tt.want) {
			gotj, _ := json.MarshalIndent(got, "", strings.Repeat(" ", 4))
			wantj, err := json.MarshalIndent(tt.want, "", strings.Repeat(" ", 4))
			if err != nil {
				t.Errorf("%s: GzipToSchema(%v): did not get expected output, and JSON generation failed: %v", tt.name, tt.in, err)
			}
			diff, _ := testutil.GenerateUnifiedDiff(string(wantj), string(gotj))
			t.Errorf("%s: GzipToSchema(%v): did not get expected output, diff(-want, +got):\n%s", tt.name, tt.in, diff)
		}
	}
}
