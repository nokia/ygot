// notification extends the Notification message from openconfig/gnmi
// to include gNMI paths for data elements that have been added.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.15.6
// source: notification.proto

package notification

import (
	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type NotificationWithAdds struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GnmiNotif *gnmi.Notification `protobuf:"bytes,1,opt,name=gnmi_notif,json=gnmiNotif,proto3" json:"gnmi_notif,omitempty"`
	Addition  *gnmi.Update       `protobuf:"bytes,2,opt,name=Addition,proto3" json:"Addition,omitempty"`
}

func (x *NotificationWithAdds) Reset() {
	*x = NotificationWithAdds{}
	if protoimpl.UnsafeEnabled {
		mi := &file_notification_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NotificationWithAdds) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NotificationWithAdds) ProtoMessage() {}

func (x *NotificationWithAdds) ProtoReflect() protoreflect.Message {
	mi := &file_notification_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NotificationWithAdds.ProtoReflect.Descriptor instead.
func (*NotificationWithAdds) Descriptor() ([]byte, []int) {
	return file_notification_proto_rawDescGZIP(), []int{0}
}

func (x *NotificationWithAdds) GetGnmiNotif() *gnmi.Notification {
	if x != nil {
		return x.GnmiNotif
	}
	return nil
}

func (x *NotificationWithAdds) GetAddition() *gnmi.Update {
	if x != nil {
		return x.Addition
	}
	return nil
}

var File_notification_proto protoreflect.FileDescriptor

var file_notification_proto_rawDesc = []byte{
	0x0a, 0x12, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x1a, 0x30, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f,
	0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x67, 0x6e, 0x6d, 0x69, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6e, 0x6d, 0x69, 0x2f, 0x67, 0x6e, 0x6d, 0x69, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0x73, 0x0a, 0x14, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x57, 0x69, 0x74, 0x68, 0x41, 0x64, 0x64, 0x73, 0x12, 0x31, 0x0a, 0x0a,
	0x67, 0x6e, 0x6d, 0x69, 0x5f, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x12, 0x2e, 0x67, 0x6e, 0x6d, 0x69, 0x2e, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x52, 0x09, 0x67, 0x6e, 0x6d, 0x69, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x12,
	0x28, 0x0a, 0x08, 0x41, 0x64, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x0c, 0x2e, 0x67, 0x6e, 0x6d, 0x69, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52,
	0x08, 0x41, 0x64, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x2f, 0x5a, 0x2d, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x2f, 0x79, 0x67, 0x6f, 0x74, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x6e, 0x6f,
	0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_notification_proto_rawDescOnce sync.Once
	file_notification_proto_rawDescData = file_notification_proto_rawDesc
)

func file_notification_proto_rawDescGZIP() []byte {
	file_notification_proto_rawDescOnce.Do(func() {
		file_notification_proto_rawDescData = protoimpl.X.CompressGZIP(file_notification_proto_rawDescData)
	})
	return file_notification_proto_rawDescData
}

var file_notification_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_notification_proto_goTypes = []interface{}{
	(*NotificationWithAdds)(nil), // 0: notification.NotificationWithAdds
	(*gnmi.Notification)(nil),    // 1: gnmi.Notification
	(*gnmi.Update)(nil),          // 2: gnmi.Update
}
var file_notification_proto_depIdxs = []int32{
	1, // 0: notification.NotificationWithAdds.gnmi_notif:type_name -> gnmi.Notification
	2, // 1: notification.NotificationWithAdds.Addition:type_name -> gnmi.Update
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_notification_proto_init() }
func file_notification_proto_init() {
	if File_notification_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_notification_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NotificationWithAdds); i {
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
			RawDescriptor: file_notification_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_notification_proto_goTypes,
		DependencyIndexes: file_notification_proto_depIdxs,
		MessageInfos:      file_notification_proto_msgTypes,
	}.Build()
	File_notification_proto = out.File
	file_notification_proto_rawDesc = nil
	file_notification_proto_goTypes = nil
	file_notification_proto_depIdxs = nil
}
