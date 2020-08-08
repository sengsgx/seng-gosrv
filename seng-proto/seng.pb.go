// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.3
// source: seng.proto

package seng_proto

import (
	proto "github.com/golang/protobuf/proto"
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

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type CliBlockerReply_Replies int32

const (
	CliBlockerReply_DENIED          CliBlockerReply_Replies = 0
	CliBlockerReply_GRANTED         CliBlockerReply_Replies = 1
	CliBlockerReply_IN_USE          CliBlockerReply_Replies = 2
	CliBlockerReply_WAS_NOT_BLOCKED CliBlockerReply_Replies = 3
	CliBlockerReply_NOW_UNLBOCKED   CliBlockerReply_Replies = 4
)

// Enum value maps for CliBlockerReply_Replies.
var (
	CliBlockerReply_Replies_name = map[int32]string{
		0: "DENIED",
		1: "GRANTED",
		2: "IN_USE",
		3: "WAS_NOT_BLOCKED",
		4: "NOW_UNLBOCKED",
	}
	CliBlockerReply_Replies_value = map[string]int32{
		"DENIED":          0,
		"GRANTED":         1,
		"IN_USE":          2,
		"WAS_NOT_BLOCKED": 3,
		"NOW_UNLBOCKED":   4,
	}
)

func (x CliBlockerReply_Replies) Enum() *CliBlockerReply_Replies {
	p := new(CliBlockerReply_Replies)
	*p = x
	return p
}

func (x CliBlockerReply_Replies) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (CliBlockerReply_Replies) Descriptor() protoreflect.EnumDescriptor {
	return file_seng_proto_enumTypes[0].Descriptor()
}

func (CliBlockerReply_Replies) Type() protoreflect.EnumType {
	return &file_seng_proto_enumTypes[0]
}

func (x CliBlockerReply_Replies) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Do not use.
func (x *CliBlockerReply_Replies) UnmarshalJSON(b []byte) error {
	num, err := protoimpl.X.UnmarshalJSONEnum(x.Descriptor(), b)
	if err != nil {
		return err
	}
	*x = CliBlockerReply_Replies(num)
	return nil
}

// Deprecated: Use CliBlockerReply_Replies.Descriptor instead.
func (CliBlockerReply_Replies) EnumDescriptor() ([]byte, []int) {
	return file_seng_proto_rawDescGZIP(), []int{4, 0}
}

type ShadowReqReply_Replies int32

const (
	ShadowReqReply_DENIED  ShadowReqReply_Replies = 0
	ShadowReqReply_GRANTED ShadowReqReply_Replies = 1
)

// Enum value maps for ShadowReqReply_Replies.
var (
	ShadowReqReply_Replies_name = map[int32]string{
		0: "DENIED",
		1: "GRANTED",
	}
	ShadowReqReply_Replies_value = map[string]int32{
		"DENIED":  0,
		"GRANTED": 1,
	}
)

func (x ShadowReqReply_Replies) Enum() *ShadowReqReply_Replies {
	p := new(ShadowReqReply_Replies)
	*p = x
	return p
}

func (x ShadowReqReply_Replies) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ShadowReqReply_Replies) Descriptor() protoreflect.EnumDescriptor {
	return file_seng_proto_enumTypes[1].Descriptor()
}

func (ShadowReqReply_Replies) Type() protoreflect.EnumType {
	return &file_seng_proto_enumTypes[1]
}

func (x ShadowReqReply_Replies) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Do not use.
func (x *ShadowReqReply_Replies) UnmarshalJSON(b []byte) error {
	num, err := protoimpl.X.UnmarshalJSONEnum(x.Descriptor(), b)
	if err != nil {
		return err
	}
	*x = ShadowReqReply_Replies(num)
	return nil
}

// Deprecated: Use ShadowReqReply_Replies.Descriptor instead.
func (ShadowReqReply_Replies) EnumDescriptor() ([]byte, []int) {
	return file_seng_proto_rawDescGZIP(), []int{5, 0}
}

type ListenStartConfirm_Replies int32

const (
	ListenStartConfirm_FAILED        ListenStartConfirm_Replies = 0
	ListenStartConfirm_NOW_LISTENING ListenStartConfirm_Replies = 1
)

// Enum value maps for ListenStartConfirm_Replies.
var (
	ListenStartConfirm_Replies_name = map[int32]string{
		0: "FAILED",
		1: "NOW_LISTENING",
	}
	ListenStartConfirm_Replies_value = map[string]int32{
		"FAILED":        0,
		"NOW_LISTENING": 1,
	}
)

func (x ListenStartConfirm_Replies) Enum() *ListenStartConfirm_Replies {
	p := new(ListenStartConfirm_Replies)
	*p = x
	return p
}

func (x ListenStartConfirm_Replies) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ListenStartConfirm_Replies) Descriptor() protoreflect.EnumDescriptor {
	return file_seng_proto_enumTypes[2].Descriptor()
}

func (ListenStartConfirm_Replies) Type() protoreflect.EnumType {
	return &file_seng_proto_enumTypes[2]
}

func (x ListenStartConfirm_Replies) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Do not use.
func (x *ListenStartConfirm_Replies) UnmarshalJSON(b []byte) error {
	num, err := protoimpl.X.UnmarshalJSONEnum(x.Descriptor(), b)
	if err != nil {
		return err
	}
	*x = ListenStartConfirm_Replies(num)
	return nil
}

// Deprecated: Use ListenStartConfirm_Replies.Descriptor instead.
func (ListenStartConfirm_Replies) EnumDescriptor() ([]byte, []int) {
	return file_seng_proto_rawDescGZIP(), []int{6, 0}
}

// Sent from NGW to Tunnel Netif (setup phase)
type IpAssignment struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ip      *uint32 `protobuf:"varint,1,req,name=ip" json:"ip,omitempty"`                 // 32bit
	Netmask *uint32 `protobuf:"varint,2,req,name=netmask" json:"netmask,omitempty"`       // 32bit
	GwIp    *uint32 `protobuf:"varint,3,req,name=gw_ip,json=gwIp" json:"gw_ip,omitempty"` // 32bit
}

func (x *IpAssignment) Reset() {
	*x = IpAssignment{}
	if protoimpl.UnsafeEnabled {
		mi := &file_seng_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IpAssignment) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IpAssignment) ProtoMessage() {}

func (x *IpAssignment) ProtoReflect() protoreflect.Message {
	mi := &file_seng_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IpAssignment.ProtoReflect.Descriptor instead.
func (*IpAssignment) Descriptor() ([]byte, []int) {
	return file_seng_proto_rawDescGZIP(), []int{0}
}

func (x *IpAssignment) GetIp() uint32 {
	if x != nil && x.Ip != nil {
		return *x.Ip
	}
	return 0
}

func (x *IpAssignment) GetNetmask() uint32 {
	if x != nil && x.Netmask != nil {
		return *x.Netmask
	}
	return 0
}

func (x *IpAssignment) GetGwIp() uint32 {
	if x != nil && x.GwIp != nil {
		return *x.GwIp
	}
	return 0
}

// Sent from Tunnel Netif to NGW (setup phase)
type IpAssignACK struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ip *uint32 `protobuf:"varint,1,req,name=ip" json:"ip,omitempty"` // 32bit
}

func (x *IpAssignACK) Reset() {
	*x = IpAssignACK{}
	if protoimpl.UnsafeEnabled {
		mi := &file_seng_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IpAssignACK) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IpAssignACK) ProtoMessage() {}

func (x *IpAssignACK) ProtoReflect() protoreflect.Message {
	mi := &file_seng_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IpAssignACK.ProtoReflect.Descriptor instead.
func (*IpAssignACK) Descriptor() ([]byte, []int) {
	return file_seng_proto_rawDescGZIP(), []int{1}
}

func (x *IpAssignACK) GetIp() uint32 {
	if x != nil && x.Ip != nil {
		return *x.Ip
	}
	return 0
}

// Sent from Enclave to NGW
type ShadowSrvMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Msg:
	//	*ShadowSrvMsg_ReqShadow
	//	*ShadowSrvMsg_CloseNotify
	Msg isShadowSrvMsg_Msg `protobuf_oneof:"msg"`
}

func (x *ShadowSrvMsg) Reset() {
	*x = ShadowSrvMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_seng_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ShadowSrvMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ShadowSrvMsg) ProtoMessage() {}

func (x *ShadowSrvMsg) ProtoReflect() protoreflect.Message {
	mi := &file_seng_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ShadowSrvMsg.ProtoReflect.Descriptor instead.
func (*ShadowSrvMsg) Descriptor() ([]byte, []int) {
	return file_seng_proto_rawDescGZIP(), []int{2}
}

func (m *ShadowSrvMsg) GetMsg() isShadowSrvMsg_Msg {
	if m != nil {
		return m.Msg
	}
	return nil
}

func (x *ShadowSrvMsg) GetReqShadow() *ShadowSrvMsg_RequestCliSockShadowing {
	if x, ok := x.GetMsg().(*ShadowSrvMsg_ReqShadow); ok {
		return x.ReqShadow
	}
	return nil
}

func (x *ShadowSrvMsg) GetCloseNotify() *ShadowSrvMsg_NotifyAboutClose {
	if x, ok := x.GetMsg().(*ShadowSrvMsg_CloseNotify); ok {
		return x.CloseNotify
	}
	return nil
}

type isShadowSrvMsg_Msg interface {
	isShadowSrvMsg_Msg()
}

type ShadowSrvMsg_ReqShadow struct {
	ReqShadow *ShadowSrvMsg_RequestCliSockShadowing `protobuf:"bytes,1,opt,name=reqShadow,oneof"`
}

type ShadowSrvMsg_CloseNotify struct {
	CloseNotify *ShadowSrvMsg_NotifyAboutClose `protobuf:"bytes,2,opt,name=closeNotify,oneof"`
}

func (*ShadowSrvMsg_ReqShadow) isShadowSrvMsg_Msg() {}

func (*ShadowSrvMsg_CloseNotify) isShadowSrvMsg_Msg() {}

// Sent from NGW to CliSB
type CliBlockerMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Msg:
	//	*CliBlockerMsg_SockBlock
	//	*CliBlockerMsg_CloseNotify_
	Msg isCliBlockerMsg_Msg `protobuf_oneof:"msg"`
}

func (x *CliBlockerMsg) Reset() {
	*x = CliBlockerMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_seng_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CliBlockerMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CliBlockerMsg) ProtoMessage() {}

func (x *CliBlockerMsg) ProtoReflect() protoreflect.Message {
	mi := &file_seng_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CliBlockerMsg.ProtoReflect.Descriptor instead.
func (*CliBlockerMsg) Descriptor() ([]byte, []int) {
	return file_seng_proto_rawDescGZIP(), []int{3}
}

func (m *CliBlockerMsg) GetMsg() isCliBlockerMsg_Msg {
	if m != nil {
		return m.Msg
	}
	return nil
}

func (x *CliBlockerMsg) GetSockBlock() *CliBlockerMsg_RequestSockBlocking {
	if x, ok := x.GetMsg().(*CliBlockerMsg_SockBlock); ok {
		return x.SockBlock
	}
	return nil
}

func (x *CliBlockerMsg) GetCloseNotify() *CliBlockerMsg_CloseNotify {
	if x, ok := x.GetMsg().(*CliBlockerMsg_CloseNotify_); ok {
		return x.CloseNotify
	}
	return nil
}

type isCliBlockerMsg_Msg interface {
	isCliBlockerMsg_Msg()
}

type CliBlockerMsg_SockBlock struct {
	SockBlock *CliBlockerMsg_RequestSockBlocking `protobuf:"bytes,1,opt,name=sockBlock,oneof"`
}

type CliBlockerMsg_CloseNotify_ struct {
	CloseNotify *CliBlockerMsg_CloseNotify `protobuf:"bytes,2,opt,name=closeNotify,oneof"`
}

func (*CliBlockerMsg_SockBlock) isCliBlockerMsg_Msg() {}

func (*CliBlockerMsg_CloseNotify_) isCliBlockerMsg_Msg() {}

// Sent from CliSB to NGW
type CliBlockerReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Reply *CliBlockerReply_Replies `protobuf:"varint,1,req,name=reply,enum=seng_proto.CliBlockerReply_Replies" json:"reply,omitempty"`
}

func (x *CliBlockerReply) Reset() {
	*x = CliBlockerReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_seng_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CliBlockerReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CliBlockerReply) ProtoMessage() {}

func (x *CliBlockerReply) ProtoReflect() protoreflect.Message {
	mi := &file_seng_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CliBlockerReply.ProtoReflect.Descriptor instead.
func (*CliBlockerReply) Descriptor() ([]byte, []int) {
	return file_seng_proto_rawDescGZIP(), []int{4}
}

func (x *CliBlockerReply) GetReply() CliBlockerReply_Replies {
	if x != nil && x.Reply != nil {
		return *x.Reply
	}
	return CliBlockerReply_DENIED
}

// Sent from NGW to Enclave
type ShadowReqReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Reply *ShadowReqReply_Replies `protobuf:"varint,1,req,name=reply,enum=seng_proto.ShadowReqReply_Replies" json:"reply,omitempty"`
}

func (x *ShadowReqReply) Reset() {
	*x = ShadowReqReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_seng_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ShadowReqReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ShadowReqReply) ProtoMessage() {}

func (x *ShadowReqReply) ProtoReflect() protoreflect.Message {
	mi := &file_seng_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ShadowReqReply.ProtoReflect.Descriptor instead.
func (*ShadowReqReply) Descriptor() ([]byte, []int) {
	return file_seng_proto_rawDescGZIP(), []int{5}
}

func (x *ShadowReqReply) GetReply() ShadowReqReply_Replies {
	if x != nil && x.Reply != nil {
		return *x.Reply
	}
	return ShadowReqReply_DENIED
}

// Sent from Enclave to NGW
type ListenStartConfirm struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Reply *ListenStartConfirm_Replies `protobuf:"varint,1,req,name=reply,enum=seng_proto.ListenStartConfirm_Replies" json:"reply,omitempty"`
}

func (x *ListenStartConfirm) Reset() {
	*x = ListenStartConfirm{}
	if protoimpl.UnsafeEnabled {
		mi := &file_seng_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListenStartConfirm) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListenStartConfirm) ProtoMessage() {}

func (x *ListenStartConfirm) ProtoReflect() protoreflect.Message {
	mi := &file_seng_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListenStartConfirm.ProtoReflect.Descriptor instead.
func (*ListenStartConfirm) Descriptor() ([]byte, []int) {
	return file_seng_proto_rawDescGZIP(), []int{6}
}

func (x *ListenStartConfirm) GetReply() ListenStartConfirm_Replies {
	if x != nil && x.Reply != nil {
		return *x.Reply
	}
	return ListenStartConfirm_FAILED
}

type ShadowSrvMsg_RequestCliSockShadowing struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Handle *uint32 `protobuf:"varint,1,req,name=handle" json:"handle,omitempty"`
	Port   *uint32 `protobuf:"varint,2,req,name=port" json:"port,omitempty"`   // 16bit
	Proto  *uint32 `protobuf:"varint,3,req,name=proto" json:"proto,omitempty"` // 8 bit
}

func (x *ShadowSrvMsg_RequestCliSockShadowing) Reset() {
	*x = ShadowSrvMsg_RequestCliSockShadowing{}
	if protoimpl.UnsafeEnabled {
		mi := &file_seng_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ShadowSrvMsg_RequestCliSockShadowing) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ShadowSrvMsg_RequestCliSockShadowing) ProtoMessage() {}

func (x *ShadowSrvMsg_RequestCliSockShadowing) ProtoReflect() protoreflect.Message {
	mi := &file_seng_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ShadowSrvMsg_RequestCliSockShadowing.ProtoReflect.Descriptor instead.
func (*ShadowSrvMsg_RequestCliSockShadowing) Descriptor() ([]byte, []int) {
	return file_seng_proto_rawDescGZIP(), []int{2, 0}
}

func (x *ShadowSrvMsg_RequestCliSockShadowing) GetHandle() uint32 {
	if x != nil && x.Handle != nil {
		return *x.Handle
	}
	return 0
}

func (x *ShadowSrvMsg_RequestCliSockShadowing) GetPort() uint32 {
	if x != nil && x.Port != nil {
		return *x.Port
	}
	return 0
}

func (x *ShadowSrvMsg_RequestCliSockShadowing) GetProto() uint32 {
	if x != nil && x.Proto != nil {
		return *x.Proto
	}
	return 0
}

type ShadowSrvMsg_NotifyAboutClose struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Handle *uint32 `protobuf:"varint,1,req,name=handle" json:"handle,omitempty"`
}

func (x *ShadowSrvMsg_NotifyAboutClose) Reset() {
	*x = ShadowSrvMsg_NotifyAboutClose{}
	if protoimpl.UnsafeEnabled {
		mi := &file_seng_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ShadowSrvMsg_NotifyAboutClose) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ShadowSrvMsg_NotifyAboutClose) ProtoMessage() {}

func (x *ShadowSrvMsg_NotifyAboutClose) ProtoReflect() protoreflect.Message {
	mi := &file_seng_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ShadowSrvMsg_NotifyAboutClose.ProtoReflect.Descriptor instead.
func (*ShadowSrvMsg_NotifyAboutClose) Descriptor() ([]byte, []int) {
	return file_seng_proto_rawDescGZIP(), []int{2, 1}
}

func (x *ShadowSrvMsg_NotifyAboutClose) GetHandle() uint32 {
	if x != nil && x.Handle != nil {
		return *x.Handle
	}
	return 0
}

type CliBlockerMsg_RequestSockBlocking struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Port      *uint32 `protobuf:"varint,1,req,name=port" json:"port,omitempty"`                           // 16bit
	Proto     *uint32 `protobuf:"varint,2,req,name=proto" json:"proto,omitempty"`                         // 8bit
	MrEnclave []byte  `protobuf:"bytes,3,req,name=mr_enclave,json=mrEnclave" json:"mr_enclave,omitempty"` // 256b = 32B = uint8_t[32]
	MrSigner  []byte  `protobuf:"bytes,4,req,name=mr_signer,json=mrSigner" json:"mr_signer,omitempty"`    // same
}

func (x *CliBlockerMsg_RequestSockBlocking) Reset() {
	*x = CliBlockerMsg_RequestSockBlocking{}
	if protoimpl.UnsafeEnabled {
		mi := &file_seng_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CliBlockerMsg_RequestSockBlocking) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CliBlockerMsg_RequestSockBlocking) ProtoMessage() {}

func (x *CliBlockerMsg_RequestSockBlocking) ProtoReflect() protoreflect.Message {
	mi := &file_seng_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CliBlockerMsg_RequestSockBlocking.ProtoReflect.Descriptor instead.
func (*CliBlockerMsg_RequestSockBlocking) Descriptor() ([]byte, []int) {
	return file_seng_proto_rawDescGZIP(), []int{3, 0}
}

func (x *CliBlockerMsg_RequestSockBlocking) GetPort() uint32 {
	if x != nil && x.Port != nil {
		return *x.Port
	}
	return 0
}

func (x *CliBlockerMsg_RequestSockBlocking) GetProto() uint32 {
	if x != nil && x.Proto != nil {
		return *x.Proto
	}
	return 0
}

func (x *CliBlockerMsg_RequestSockBlocking) GetMrEnclave() []byte {
	if x != nil {
		return x.MrEnclave
	}
	return nil
}

func (x *CliBlockerMsg_RequestSockBlocking) GetMrSigner() []byte {
	if x != nil {
		return x.MrSigner
	}
	return nil
}

type CliBlockerMsg_CloseNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Port  *uint32 `protobuf:"varint,1,req,name=port" json:"port,omitempty"`   // 16bit
	Proto *uint32 `protobuf:"varint,2,req,name=proto" json:"proto,omitempty"` // 8bit
}

func (x *CliBlockerMsg_CloseNotify) Reset() {
	*x = CliBlockerMsg_CloseNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_seng_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CliBlockerMsg_CloseNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CliBlockerMsg_CloseNotify) ProtoMessage() {}

func (x *CliBlockerMsg_CloseNotify) ProtoReflect() protoreflect.Message {
	mi := &file_seng_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CliBlockerMsg_CloseNotify.ProtoReflect.Descriptor instead.
func (*CliBlockerMsg_CloseNotify) Descriptor() ([]byte, []int) {
	return file_seng_proto_rawDescGZIP(), []int{3, 1}
}

func (x *CliBlockerMsg_CloseNotify) GetPort() uint32 {
	if x != nil && x.Port != nil {
		return *x.Port
	}
	return 0
}

func (x *CliBlockerMsg_CloseNotify) GetProto() uint32 {
	if x != nil && x.Proto != nil {
		return *x.Proto
	}
	return 0
}

var File_seng_proto protoreflect.FileDescriptor

var file_seng_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x73, 0x65, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0a, 0x73, 0x65,
	0x6e, 0x67, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x4d, 0x0a, 0x0c, 0x49, 0x70, 0x41, 0x73,
	0x73, 0x69, 0x67, 0x6e, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x70, 0x18, 0x01,
	0x20, 0x02, 0x28, 0x0d, 0x52, 0x02, 0x69, 0x70, 0x12, 0x18, 0x0a, 0x07, 0x6e, 0x65, 0x74, 0x6d,
	0x61, 0x73, 0x6b, 0x18, 0x02, 0x20, 0x02, 0x28, 0x0d, 0x52, 0x07, 0x6e, 0x65, 0x74, 0x6d, 0x61,
	0x73, 0x6b, 0x12, 0x13, 0x0a, 0x05, 0x67, 0x77, 0x5f, 0x69, 0x70, 0x18, 0x03, 0x20, 0x02, 0x28,
	0x0d, 0x52, 0x04, 0x67, 0x77, 0x49, 0x70, 0x22, 0x1d, 0x0a, 0x0b, 0x49, 0x70, 0x41, 0x73, 0x73,
	0x69, 0x67, 0x6e, 0x41, 0x43, 0x4b, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x70, 0x18, 0x01, 0x20, 0x02,
	0x28, 0x0d, 0x52, 0x02, 0x69, 0x70, 0x22, 0xbf, 0x02, 0x0a, 0x0c, 0x53, 0x68, 0x61, 0x64, 0x6f,
	0x77, 0x53, 0x72, 0x76, 0x4d, 0x73, 0x67, 0x12, 0x50, 0x0a, 0x09, 0x72, 0x65, 0x71, 0x53, 0x68,
	0x61, 0x64, 0x6f, 0x77, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x30, 0x2e, 0x73, 0x65, 0x6e,
	0x67, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x53, 0x68, 0x61, 0x64, 0x6f, 0x77, 0x53, 0x72,
	0x76, 0x4d, 0x73, 0x67, 0x2e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x43, 0x6c, 0x69, 0x53,
	0x6f, 0x63, 0x6b, 0x53, 0x68, 0x61, 0x64, 0x6f, 0x77, 0x69, 0x6e, 0x67, 0x48, 0x00, 0x52, 0x09,
	0x72, 0x65, 0x71, 0x53, 0x68, 0x61, 0x64, 0x6f, 0x77, 0x12, 0x4d, 0x0a, 0x0b, 0x63, 0x6c, 0x6f,
	0x73, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x29,
	0x2e, 0x73, 0x65, 0x6e, 0x67, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x53, 0x68, 0x61, 0x64,
	0x6f, 0x77, 0x53, 0x72, 0x76, 0x4d, 0x73, 0x67, 0x2e, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x41,
	0x62, 0x6f, 0x75, 0x74, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0x48, 0x00, 0x52, 0x0b, 0x63, 0x6c, 0x6f,
	0x73, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x1a, 0x5b, 0x0a, 0x17, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x43, 0x6c, 0x69, 0x53, 0x6f, 0x63, 0x6b, 0x53, 0x68, 0x61, 0x64, 0x6f, 0x77,
	0x69, 0x6e, 0x67, 0x12, 0x16, 0x0a, 0x06, 0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x18, 0x01, 0x20,
	0x02, 0x28, 0x0d, 0x52, 0x06, 0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x70,
	0x6f, 0x72, 0x74, 0x18, 0x02, 0x20, 0x02, 0x28, 0x0d, 0x52, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x12,
	0x14, 0x0a, 0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x18, 0x03, 0x20, 0x02, 0x28, 0x0d, 0x52, 0x05,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2a, 0x0a, 0x10, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x41,
	0x62, 0x6f, 0x75, 0x74, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x68, 0x61, 0x6e,
	0x64, 0x6c, 0x65, 0x18, 0x01, 0x20, 0x02, 0x28, 0x0d, 0x52, 0x06, 0x68, 0x61, 0x6e, 0x64, 0x6c,
	0x65, 0x42, 0x05, 0x0a, 0x03, 0x6d, 0x73, 0x67, 0x22, 0xe6, 0x02, 0x0a, 0x0d, 0x43, 0x6c, 0x69,
	0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x72, 0x4d, 0x73, 0x67, 0x12, 0x4d, 0x0a, 0x09, 0x73, 0x6f,
	0x63, 0x6b, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e,
	0x73, 0x65, 0x6e, 0x67, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x43, 0x6c, 0x69, 0x42, 0x6c,
	0x6f, 0x63, 0x6b, 0x65, 0x72, 0x4d, 0x73, 0x67, 0x2e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x53, 0x6f, 0x63, 0x6b, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x48, 0x00, 0x52, 0x09,
	0x73, 0x6f, 0x63, 0x6b, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x12, 0x49, 0x0a, 0x0b, 0x63, 0x6c, 0x6f,
	0x73, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x25,
	0x2e, 0x73, 0x65, 0x6e, 0x67, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x43, 0x6c, 0x69, 0x42,
	0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x72, 0x4d, 0x73, 0x67, 0x2e, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0x4e,
	0x6f, 0x74, 0x69, 0x66, 0x79, 0x48, 0x00, 0x52, 0x0b, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x4e, 0x6f,
	0x74, 0x69, 0x66, 0x79, 0x1a, 0x7b, 0x0a, 0x13, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x53,
	0x6f, 0x63, 0x6b, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x12, 0x12, 0x0a, 0x04, 0x70,
	0x6f, 0x72, 0x74, 0x18, 0x01, 0x20, 0x02, 0x28, 0x0d, 0x52, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x12,
	0x14, 0x0a, 0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x18, 0x02, 0x20, 0x02, 0x28, 0x0d, 0x52, 0x05,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1d, 0x0a, 0x0a, 0x6d, 0x72, 0x5f, 0x65, 0x6e, 0x63, 0x6c,
	0x61, 0x76, 0x65, 0x18, 0x03, 0x20, 0x02, 0x28, 0x0c, 0x52, 0x09, 0x6d, 0x72, 0x45, 0x6e, 0x63,
	0x6c, 0x61, 0x76, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x6d, 0x72, 0x5f, 0x73, 0x69, 0x67, 0x6e, 0x65,
	0x72, 0x18, 0x04, 0x20, 0x02, 0x28, 0x0c, 0x52, 0x08, 0x6d, 0x72, 0x53, 0x69, 0x67, 0x6e, 0x65,
	0x72, 0x1a, 0x37, 0x0a, 0x0b, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79,
	0x12, 0x12, 0x0a, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x01, 0x20, 0x02, 0x28, 0x0d, 0x52, 0x04,
	0x70, 0x6f, 0x72, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x18, 0x02, 0x20,
	0x02, 0x28, 0x0d, 0x52, 0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x42, 0x05, 0x0a, 0x03, 0x6d, 0x73,
	0x67, 0x22, 0xa4, 0x01, 0x0a, 0x0f, 0x43, 0x6c, 0x69, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x72,
	0x52, 0x65, 0x70, 0x6c, 0x79, 0x12, 0x39, 0x0a, 0x05, 0x72, 0x65, 0x70, 0x6c, 0x79, 0x18, 0x01,
	0x20, 0x02, 0x28, 0x0e, 0x32, 0x23, 0x2e, 0x73, 0x65, 0x6e, 0x67, 0x5f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2e, 0x43, 0x6c, 0x69, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x72, 0x52, 0x65, 0x70, 0x6c,
	0x79, 0x2e, 0x52, 0x65, 0x70, 0x6c, 0x69, 0x65, 0x73, 0x52, 0x05, 0x72, 0x65, 0x70, 0x6c, 0x79,
	0x22, 0x56, 0x0a, 0x07, 0x52, 0x65, 0x70, 0x6c, 0x69, 0x65, 0x73, 0x12, 0x0a, 0x0a, 0x06, 0x44,
	0x45, 0x4e, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x0b, 0x0a, 0x07, 0x47, 0x52, 0x41, 0x4e, 0x54,
	0x45, 0x44, 0x10, 0x01, 0x12, 0x0a, 0x0a, 0x06, 0x49, 0x4e, 0x5f, 0x55, 0x53, 0x45, 0x10, 0x02,
	0x12, 0x13, 0x0a, 0x0f, 0x57, 0x41, 0x53, 0x5f, 0x4e, 0x4f, 0x54, 0x5f, 0x42, 0x4c, 0x4f, 0x43,
	0x4b, 0x45, 0x44, 0x10, 0x03, 0x12, 0x11, 0x0a, 0x0d, 0x4e, 0x4f, 0x57, 0x5f, 0x55, 0x4e, 0x4c,
	0x42, 0x4f, 0x43, 0x4b, 0x45, 0x44, 0x10, 0x04, 0x22, 0x6e, 0x0a, 0x0e, 0x53, 0x68, 0x61, 0x64,
	0x6f, 0x77, 0x52, 0x65, 0x71, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x12, 0x38, 0x0a, 0x05, 0x72, 0x65,
	0x70, 0x6c, 0x79, 0x18, 0x01, 0x20, 0x02, 0x28, 0x0e, 0x32, 0x22, 0x2e, 0x73, 0x65, 0x6e, 0x67,
	0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x53, 0x68, 0x61, 0x64, 0x6f, 0x77, 0x52, 0x65, 0x71,
	0x52, 0x65, 0x70, 0x6c, 0x79, 0x2e, 0x52, 0x65, 0x70, 0x6c, 0x69, 0x65, 0x73, 0x52, 0x05, 0x72,
	0x65, 0x70, 0x6c, 0x79, 0x22, 0x22, 0x0a, 0x07, 0x52, 0x65, 0x70, 0x6c, 0x69, 0x65, 0x73, 0x12,
	0x0a, 0x0a, 0x06, 0x44, 0x45, 0x4e, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x0b, 0x0a, 0x07, 0x47,
	0x52, 0x41, 0x4e, 0x54, 0x45, 0x44, 0x10, 0x01, 0x22, 0x7c, 0x0a, 0x12, 0x4c, 0x69, 0x73, 0x74,
	0x65, 0x6e, 0x53, 0x74, 0x61, 0x72, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x12, 0x3c,
	0x0a, 0x05, 0x72, 0x65, 0x70, 0x6c, 0x79, 0x18, 0x01, 0x20, 0x02, 0x28, 0x0e, 0x32, 0x26, 0x2e,
	0x73, 0x65, 0x6e, 0x67, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x65,
	0x6e, 0x53, 0x74, 0x61, 0x72, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x2e, 0x52, 0x65,
	0x70, 0x6c, 0x69, 0x65, 0x73, 0x52, 0x05, 0x72, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x28, 0x0a, 0x07,
	0x52, 0x65, 0x70, 0x6c, 0x69, 0x65, 0x73, 0x12, 0x0a, 0x0a, 0x06, 0x46, 0x41, 0x49, 0x4c, 0x45,
	0x44, 0x10, 0x00, 0x12, 0x11, 0x0a, 0x0d, 0x4e, 0x4f, 0x57, 0x5f, 0x4c, 0x49, 0x53, 0x54, 0x45,
	0x4e, 0x49, 0x4e, 0x47, 0x10, 0x01,
}

var (
	file_seng_proto_rawDescOnce sync.Once
	file_seng_proto_rawDescData = file_seng_proto_rawDesc
)

func file_seng_proto_rawDescGZIP() []byte {
	file_seng_proto_rawDescOnce.Do(func() {
		file_seng_proto_rawDescData = protoimpl.X.CompressGZIP(file_seng_proto_rawDescData)
	})
	return file_seng_proto_rawDescData
}

var file_seng_proto_enumTypes = make([]protoimpl.EnumInfo, 3)
var file_seng_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_seng_proto_goTypes = []interface{}{
	(CliBlockerReply_Replies)(0),                 // 0: seng_proto.CliBlockerReply.Replies
	(ShadowReqReply_Replies)(0),                  // 1: seng_proto.ShadowReqReply.Replies
	(ListenStartConfirm_Replies)(0),              // 2: seng_proto.ListenStartConfirm.Replies
	(*IpAssignment)(nil),                         // 3: seng_proto.IpAssignment
	(*IpAssignACK)(nil),                          // 4: seng_proto.IpAssignACK
	(*ShadowSrvMsg)(nil),                         // 5: seng_proto.ShadowSrvMsg
	(*CliBlockerMsg)(nil),                        // 6: seng_proto.CliBlockerMsg
	(*CliBlockerReply)(nil),                      // 7: seng_proto.CliBlockerReply
	(*ShadowReqReply)(nil),                       // 8: seng_proto.ShadowReqReply
	(*ListenStartConfirm)(nil),                   // 9: seng_proto.ListenStartConfirm
	(*ShadowSrvMsg_RequestCliSockShadowing)(nil), // 10: seng_proto.ShadowSrvMsg.RequestCliSockShadowing
	(*ShadowSrvMsg_NotifyAboutClose)(nil),        // 11: seng_proto.ShadowSrvMsg.NotifyAboutClose
	(*CliBlockerMsg_RequestSockBlocking)(nil),    // 12: seng_proto.CliBlockerMsg.RequestSockBlocking
	(*CliBlockerMsg_CloseNotify)(nil),            // 13: seng_proto.CliBlockerMsg.CloseNotify
}
var file_seng_proto_depIdxs = []int32{
	10, // 0: seng_proto.ShadowSrvMsg.reqShadow:type_name -> seng_proto.ShadowSrvMsg.RequestCliSockShadowing
	11, // 1: seng_proto.ShadowSrvMsg.closeNotify:type_name -> seng_proto.ShadowSrvMsg.NotifyAboutClose
	12, // 2: seng_proto.CliBlockerMsg.sockBlock:type_name -> seng_proto.CliBlockerMsg.RequestSockBlocking
	13, // 3: seng_proto.CliBlockerMsg.closeNotify:type_name -> seng_proto.CliBlockerMsg.CloseNotify
	0,  // 4: seng_proto.CliBlockerReply.reply:type_name -> seng_proto.CliBlockerReply.Replies
	1,  // 5: seng_proto.ShadowReqReply.reply:type_name -> seng_proto.ShadowReqReply.Replies
	2,  // 6: seng_proto.ListenStartConfirm.reply:type_name -> seng_proto.ListenStartConfirm.Replies
	7,  // [7:7] is the sub-list for method output_type
	7,  // [7:7] is the sub-list for method input_type
	7,  // [7:7] is the sub-list for extension type_name
	7,  // [7:7] is the sub-list for extension extendee
	0,  // [0:7] is the sub-list for field type_name
}

func init() { file_seng_proto_init() }
func file_seng_proto_init() {
	if File_seng_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_seng_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IpAssignment); i {
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
		file_seng_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IpAssignACK); i {
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
		file_seng_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ShadowSrvMsg); i {
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
		file_seng_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CliBlockerMsg); i {
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
		file_seng_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CliBlockerReply); i {
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
		file_seng_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ShadowReqReply); i {
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
		file_seng_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListenStartConfirm); i {
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
		file_seng_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ShadowSrvMsg_RequestCliSockShadowing); i {
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
		file_seng_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ShadowSrvMsg_NotifyAboutClose); i {
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
		file_seng_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CliBlockerMsg_RequestSockBlocking); i {
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
		file_seng_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CliBlockerMsg_CloseNotify); i {
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
	file_seng_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*ShadowSrvMsg_ReqShadow)(nil),
		(*ShadowSrvMsg_CloseNotify)(nil),
	}
	file_seng_proto_msgTypes[3].OneofWrappers = []interface{}{
		(*CliBlockerMsg_SockBlock)(nil),
		(*CliBlockerMsg_CloseNotify_)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_seng_proto_rawDesc,
			NumEnums:      3,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_seng_proto_goTypes,
		DependencyIndexes: file_seng_proto_depIdxs,
		EnumInfos:         file_seng_proto_enumTypes,
		MessageInfos:      file_seng_proto_msgTypes,
	}.Build()
	File_seng_proto = out.File
	file_seng_proto_rawDesc = nil
	file_seng_proto_goTypes = nil
	file_seng_proto_depIdxs = nil
}
