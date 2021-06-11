// Copyright 2020 Google Inc.
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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.20.0-devel
// 	protoc        v3.11.4
// source: github.com/nokia/ygot/integration_tests/annotations/apb/annotation.proto

package apb

import (
	reflect "reflect"
	sync "sync"

	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type Annotation struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Comment string `protobuf:"bytes,1,opt,name=comment,proto3" json:"comment,omitempty"`
}

func (x *Annotation) Reset() {
	*x = Annotation{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Annotation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Annotation) ProtoMessage() {}

func (x *Annotation) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Annotation.ProtoReflect.Descriptor instead.
func (*Annotation) Descriptor() ([]byte, []int) {
	return file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_rawDescGZIP(), []int{0}
}

func (x *Annotation) GetComment() string {
	if x != nil {
		return x.Comment
	}
	return ""
}

var File_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto protoreflect.FileDescriptor

var file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_rawDesc = []byte{
	0x0a, 0x4d, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x70, 0x65,
	0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x79, 0x67, 0x6f, 0x74, 0x2f, 0x69, 0x6e, 0x74,
	0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x74, 0x65, 0x73, 0x74, 0x73, 0x2f, 0x61,
	0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x61, 0x70, 0x62, 0x2f, 0x61,
	0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x0a, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x26, 0x0a, 0x0a, 0x41,
	0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x6d,
	0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x6f, 0x6d, 0x6d,
	0x65, 0x6e, 0x74, 0x42, 0x3e, 0x5a, 0x3c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x79, 0x67, 0x6f,
	0x74, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x74, 0x65,
	0x73, 0x74, 0x73, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f,
	0x61, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_rawDescOnce sync.Once
	file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_rawDescData = file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_rawDesc
)

func file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_rawDescGZIP() []byte {
	file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_rawDescOnce.Do(func() {
		file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_rawDescData = protoimpl.X.CompressGZIP(
			file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_rawDescData,
		)
	})
	return file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_rawDescData
}

var file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_goTypes = []interface{}{
	(*Annotation)(nil), // 0: annotation.Annotation
}
var file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() {
	file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_init()
}
func file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_init() {
	if File_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Annotation); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_goTypes,
		DependencyIndexes: file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_depIdxs,
		MessageInfos:      file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_msgTypes,
	}.Build()
	File_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto = out.File
	file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_rawDesc = nil
	file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_goTypes = nil
	file_github_com_openconfig_ygot_integration_tests_annotations_apb_annotation_proto_depIdxs = nil
}
