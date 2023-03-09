//*
// Copyright (C) 2020 Open Whisper Systems
//
// Licensed according to the LICENSE file in this repository.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.12
// source: ResumableUploads.proto

package signalservice

import (
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

type ResumableUpload struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SecretKey []byte `protobuf:"bytes,1,opt,name=secretKey,proto3" json:"secretKey,omitempty"`
	Iv        []byte `protobuf:"bytes,2,opt,name=iv,proto3" json:"iv,omitempty"`
	CdnKey    string `protobuf:"bytes,3,opt,name=cdnKey,proto3" json:"cdnKey,omitempty"`
	CdnNumber uint32 `protobuf:"varint,4,opt,name=cdnNumber,proto3" json:"cdnNumber,omitempty"`
	Location  string `protobuf:"bytes,5,opt,name=location,proto3" json:"location,omitempty"`
	Timeout   uint64 `protobuf:"varint,6,opt,name=timeout,proto3" json:"timeout,omitempty"`
}

func (x *ResumableUpload) Reset() {
	*x = ResumableUpload{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ResumableUploads_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ResumableUpload) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResumableUpload) ProtoMessage() {}

func (x *ResumableUpload) ProtoReflect() protoreflect.Message {
	mi := &file_ResumableUploads_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ResumableUpload.ProtoReflect.Descriptor instead.
func (*ResumableUpload) Descriptor() ([]byte, []int) {
	return file_ResumableUploads_proto_rawDescGZIP(), []int{0}
}

func (x *ResumableUpload) GetSecretKey() []byte {
	if x != nil {
		return x.SecretKey
	}
	return nil
}

func (x *ResumableUpload) GetIv() []byte {
	if x != nil {
		return x.Iv
	}
	return nil
}

func (x *ResumableUpload) GetCdnKey() string {
	if x != nil {
		return x.CdnKey
	}
	return ""
}

func (x *ResumableUpload) GetCdnNumber() uint32 {
	if x != nil {
		return x.CdnNumber
	}
	return 0
}

func (x *ResumableUpload) GetLocation() string {
	if x != nil {
		return x.Location
	}
	return ""
}

func (x *ResumableUpload) GetTimeout() uint64 {
	if x != nil {
		return x.Timeout
	}
	return 0
}

var File_ResumableUploads_proto protoreflect.FileDescriptor

var file_ResumableUploads_proto_rawDesc = []byte{
	0x0a, 0x16, 0x52, 0x65, 0x73, 0x75, 0x6d, 0x61, 0x62, 0x6c, 0x65, 0x55, 0x70, 0x6c, 0x6f, 0x61,
	0x64, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xab, 0x01, 0x0a, 0x0f, 0x52, 0x65, 0x73,
	0x75, 0x6d, 0x61, 0x62, 0x6c, 0x65, 0x55, 0x70, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x1c, 0x0a, 0x09,
	0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x4b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x09, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x4b, 0x65, 0x79, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x76,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x69, 0x76, 0x12, 0x16, 0x0a, 0x06, 0x63, 0x64,
	0x6e, 0x4b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x63, 0x64, 0x6e, 0x4b,
	0x65, 0x79, 0x12, 0x1c, 0x0a, 0x09, 0x63, 0x64, 0x6e, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x63, 0x64, 0x6e, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72,
	0x12, 0x1a, 0x0a, 0x08, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x08, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x18, 0x0a, 0x07,
	0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x74,
	0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x42, 0x35, 0x0a, 0x22, 0x6f, 0x72, 0x67, 0x2e, 0x73, 0x69,
	0x67, 0x6e, 0x61, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x72, 0x65, 0x73, 0x75,
	0x6d, 0x61, 0x62, 0x6c, 0x65, 0x75, 0x70, 0x6c, 0x6f, 0x61, 0x64, 0x73, 0x5a, 0x0f, 0x2e, 0x3b,
	0x73, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ResumableUploads_proto_rawDescOnce sync.Once
	file_ResumableUploads_proto_rawDescData = file_ResumableUploads_proto_rawDesc
)

func file_ResumableUploads_proto_rawDescGZIP() []byte {
	file_ResumableUploads_proto_rawDescOnce.Do(func() {
		file_ResumableUploads_proto_rawDescData = protoimpl.X.CompressGZIP(file_ResumableUploads_proto_rawDescData)
	})
	return file_ResumableUploads_proto_rawDescData
}

var file_ResumableUploads_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_ResumableUploads_proto_goTypes = []interface{}{
	(*ResumableUpload)(nil), // 0: ResumableUpload
}
var file_ResumableUploads_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_ResumableUploads_proto_init() }
func file_ResumableUploads_proto_init() {
	if File_ResumableUploads_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ResumableUploads_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ResumableUpload); i {
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
			RawDescriptor: file_ResumableUploads_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ResumableUploads_proto_goTypes,
		DependencyIndexes: file_ResumableUploads_proto_depIdxs,
		MessageInfos:      file_ResumableUploads_proto_msgTypes,
	}.Build()
	File_ResumableUploads_proto = out.File
	file_ResumableUploads_proto_rawDesc = nil
	file_ResumableUploads_proto_goTypes = nil
	file_ResumableUploads_proto_depIdxs = nil
}
