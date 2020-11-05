// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: podinfo_api.proto

package proto

import (
	context "context"
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// Address structure describes a single instance of an address assigned to the pod
type Address struct {
	Addr                 []byte   `protobuf:"bytes,1,opt,name=addr,proto3" json:"addr,omitempty"`
	MaskLen              int32    `protobuf:"varint,2,opt,name=mask_len,json=maskLen,proto3" json:"mask_len,omitempty"`
	IsIpv6               bool     `protobuf:"varint,3,opt,name=is_ipv6,json=isIpv6,proto3" json:"is_ipv6,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Address) Reset()         { *m = Address{} }
func (m *Address) String() string { return proto.CompactTextString(m) }
func (*Address) ProtoMessage()    {}
func (*Address) Descriptor() ([]byte, []int) {
	return fileDescriptor_1cdd5668acb30bba, []int{0}
}
func (m *Address) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Address.Unmarshal(m, b)
}
func (m *Address) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Address.Marshal(b, m, deterministic)
}
func (m *Address) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Address.Merge(m, src)
}
func (m *Address) XXX_Size() int {
	return xxx_messageInfo_Address.Size(m)
}
func (m *Address) XXX_DiscardUnknown() {
	xxx_messageInfo_Address.DiscardUnknown(m)
}

var xxx_messageInfo_Address proto.InternalMessageInfo

func (m *Address) GetAddr() []byte {
	if m != nil {
		return m.Addr
	}
	return nil
}

func (m *Address) GetMaskLen() int32 {
	if m != nil {
		return m.MaskLen
	}
	return 0
}

func (m *Address) GetIsIpv6() bool {
	if m != nil {
		return m.IsIpv6
	}
	return false
}

// PodInfo structure describes information returning by gRPC server with details
// about requested pod
type PodInfo struct {
	TableId              int32      `protobuf:"varint,1,opt,name=table_id,json=tableId,proto3" json:"table_id,omitempty"`
	PortName             string     `protobuf:"bytes,2,opt,name=port_name,json=portName,proto3" json:"port_name,omitempty"`
	PodAddr              []*Address `protobuf:"bytes,3,rep,name=pod_addr,json=podAddr,proto3" json:"pod_addr,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *PodInfo) Reset()         { *m = PodInfo{} }
func (m *PodInfo) String() string { return proto.CompactTextString(m) }
func (*PodInfo) ProtoMessage()    {}
func (*PodInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_1cdd5668acb30bba, []int{1}
}
func (m *PodInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PodInfo.Unmarshal(m, b)
}
func (m *PodInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PodInfo.Marshal(b, m, deterministic)
}
func (m *PodInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PodInfo.Merge(m, src)
}
func (m *PodInfo) XXX_Size() int {
	return xxx_messageInfo_PodInfo.Size(m)
}
func (m *PodInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_PodInfo.DiscardUnknown(m)
}

var xxx_messageInfo_PodInfo proto.InternalMessageInfo

func (m *PodInfo) GetTableId() int32 {
	if m != nil {
		return m.TableId
	}
	return 0
}

func (m *PodInfo) GetPortName() string {
	if m != nil {
		return m.PortName
	}
	return ""
}

func (m *PodInfo) GetPodAddr() []*Address {
	if m != nil {
		return m.PodAddr
	}
	return nil
}

// PodInfoReq structure describes information sent to gRPC server, it includes:
// request id - to track requests, namespace - pod's actual namespace,
// and pod id - the actual pod's UUID.
type PodInfoReq struct {
	ReqId                int32    `protobuf:"varint,1,opt,name=req_id,json=reqId,proto3" json:"req_id,omitempty"`
	Namespace            string   `protobuf:"bytes,2,opt,name=namespace,proto3" json:"namespace,omitempty"`
	PodId                string   `protobuf:"bytes,3,opt,name=pod_id,json=podId,proto3" json:"pod_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PodInfoReq) Reset()         { *m = PodInfoReq{} }
func (m *PodInfoReq) String() string { return proto.CompactTextString(m) }
func (*PodInfoReq) ProtoMessage()    {}
func (*PodInfoReq) Descriptor() ([]byte, []int) {
	return fileDescriptor_1cdd5668acb30bba, []int{2}
}
func (m *PodInfoReq) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PodInfoReq.Unmarshal(m, b)
}
func (m *PodInfoReq) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PodInfoReq.Marshal(b, m, deterministic)
}
func (m *PodInfoReq) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PodInfoReq.Merge(m, src)
}
func (m *PodInfoReq) XXX_Size() int {
	return xxx_messageInfo_PodInfoReq.Size(m)
}
func (m *PodInfoReq) XXX_DiscardUnknown() {
	xxx_messageInfo_PodInfoReq.DiscardUnknown(m)
}

var xxx_messageInfo_PodInfoReq proto.InternalMessageInfo

func (m *PodInfoReq) GetReqId() int32 {
	if m != nil {
		return m.ReqId
	}
	return 0
}

func (m *PodInfoReq) GetNamespace() string {
	if m != nil {
		return m.Namespace
	}
	return ""
}

func (m *PodInfoReq) GetPodId() string {
	if m != nil {
		return m.PodId
	}
	return ""
}

// PodInfoRepl structure describes information returned by gRPC server to
// the requesting process.
// In case of a failure of getting requested pod's info, gRPC server returns
// a number error code and well as details error desccription.
type PodInfoRepl struct {
	PodInfo              *PodInfo `protobuf:"bytes,1,opt,name=pod_info,json=podInfo,proto3" json:"pod_info,omitempty"`
	Err                  int32    `protobuf:"varint,2,opt,name=err,proto3" json:"err,omitempty"`
	ErrDetail            string   `protobuf:"bytes,3,opt,name=err_detail,json=errDetail,proto3" json:"err_detail,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PodInfoRepl) Reset()         { *m = PodInfoRepl{} }
func (m *PodInfoRepl) String() string { return proto.CompactTextString(m) }
func (*PodInfoRepl) ProtoMessage()    {}
func (*PodInfoRepl) Descriptor() ([]byte, []int) {
	return fileDescriptor_1cdd5668acb30bba, []int{3}
}
func (m *PodInfoRepl) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PodInfoRepl.Unmarshal(m, b)
}
func (m *PodInfoRepl) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PodInfoRepl.Marshal(b, m, deterministic)
}
func (m *PodInfoRepl) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PodInfoRepl.Merge(m, src)
}
func (m *PodInfoRepl) XXX_Size() int {
	return xxx_messageInfo_PodInfoRepl.Size(m)
}
func (m *PodInfoRepl) XXX_DiscardUnknown() {
	xxx_messageInfo_PodInfoRepl.DiscardUnknown(m)
}

var xxx_messageInfo_PodInfoRepl proto.InternalMessageInfo

func (m *PodInfoRepl) GetPodInfo() *PodInfo {
	if m != nil {
		return m.PodInfo
	}
	return nil
}

func (m *PodInfoRepl) GetErr() int32 {
	if m != nil {
		return m.Err
	}
	return 0
}

func (m *PodInfoRepl) GetErrDetail() string {
	if m != nil {
		return m.ErrDetail
	}
	return ""
}

func init() {
	proto.RegisterType((*Address)(nil), "proto.Address")
	proto.RegisterType((*PodInfo)(nil), "proto.PodInfo")
	proto.RegisterType((*PodInfoReq)(nil), "proto.PodInfoReq")
	proto.RegisterType((*PodInfoRepl)(nil), "proto.PodInfoRepl")
}

func init() { proto.RegisterFile("podinfo_api.proto", fileDescriptor_1cdd5668acb30bba) }

var fileDescriptor_1cdd5668acb30bba = []byte{
	// 325 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x5c, 0x51, 0x4b, 0x6b, 0xe3, 0x30,
	0x10, 0xc6, 0xeb, 0x75, 0x64, 0x4f, 0x96, 0x65, 0x23, 0x58, 0x9a, 0xbe, 0xc0, 0xf8, 0xe4, 0x42,
	0xc9, 0x21, 0x85, 0x1c, 0x7a, 0x6b, 0x29, 0x14, 0x43, 0x29, 0xad, 0x7a, 0x29, 0xbd, 0x08, 0x25,
	0x33, 0x01, 0x51, 0xc7, 0x92, 0x65, 0x93, 0xdf, 0x5f, 0xa4, 0x38, 0x09, 0xe4, 0x34, 0x33, 0x1f,
	0x9a, 0xef, 0x31, 0x82, 0x89, 0x35, 0xa8, 0x9b, 0xb5, 0x91, 0xca, 0xea, 0x99, 0x75, 0xa6, 0x37,
	0x3c, 0x09, 0xa5, 0x78, 0x07, 0xf6, 0x80, 0xe8, 0xa8, 0xeb, 0x38, 0x87, 0xdf, 0x0a, 0xd1, 0x4d,
	0xa3, 0x3c, 0x2a, 0xff, 0x88, 0xd0, 0xf3, 0x73, 0x48, 0x37, 0xaa, 0xfb, 0x96, 0x35, 0x35, 0xd3,
	0x5f, 0x79, 0x54, 0x26, 0x82, 0xf9, 0xf9, 0x85, 0x1a, 0x7e, 0x06, 0x4c, 0x77, 0x52, 0xdb, 0xed,
	0x62, 0x1a, 0xe7, 0x51, 0x99, 0x8a, 0x91, 0xee, 0x2a, 0xbb, 0x5d, 0x14, 0x35, 0xb0, 0x37, 0x83,
	0x55, 0xb3, 0x36, 0x7e, 0xbd, 0x57, 0xcb, 0x9a, 0xa4, 0xc6, 0x40, 0x9b, 0x08, 0x16, 0xe6, 0x0a,
	0xf9, 0x25, 0x64, 0xd6, 0xb8, 0x5e, 0x36, 0x6a, 0x43, 0x81, 0x3a, 0x13, 0xa9, 0x07, 0x5e, 0xd5,
	0x86, 0xf8, 0x0d, 0xa4, 0xd6, 0xa0, 0x0c, 0x76, 0xe2, 0x3c, 0x2e, 0xc7, 0xf3, 0xbf, 0x3b, 0xdb,
	0xb3, 0xc1, 0xac, 0x60, 0xd6, 0xa0, 0xef, 0x8b, 0x4f, 0x80, 0x41, 0x4d, 0x50, 0xcb, 0xff, 0xc3,
	0xc8, 0x51, 0x7b, 0x94, 0x4b, 0x1c, 0xb5, 0x15, 0xf2, 0x2b, 0xc8, 0xbc, 0x4e, 0x67, 0xd5, 0x6a,
	0x2f, 0x76, 0x04, 0xfc, 0x92, 0x57, 0xd3, 0x18, 0x82, 0x64, 0x22, 0xb1, 0x06, 0x2b, 0x2c, 0x34,
	0x8c, 0x0f, 0xcc, 0xb6, 0xde, 0x7b, 0xf2, 0x67, 0x0c, 0xe4, 0x47, 0x4f, 0xfb, 0x57, 0xde, 0x53,
	0x88, 0xfd, 0x0f, 0x62, 0x72, 0x6e, 0x38, 0x98, 0x6f, 0xf9, 0x35, 0x00, 0x39, 0x27, 0x91, 0x7a,
	0xa5, 0xeb, 0x41, 0x26, 0x23, 0xe7, 0x9e, 0x02, 0x30, 0xbf, 0x3f, 0x84, 0xf8, 0xd8, 0xae, 0xf8,
	0x2d, 0xc4, 0xcf, 0xd4, 0xf3, 0xc9, 0x09, 0x3d, 0xb5, 0x17, 0xfc, 0x14, 0xb2, 0xf5, 0x23, 0xfb,
	0xda, 0x7d, 0xe5, 0x72, 0x14, 0xca, 0xdd, 0x4f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x8e, 0x4b, 0xe4,
	0xf3, 0xed, 0x01, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// PodInfoSvcClient is the client API for PodInfoSvc service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type PodInfoSvcClient interface {
	Get(ctx context.Context, in *PodInfoReq, opts ...grpc.CallOption) (*PodInfoRepl, error)
}

type podInfoSvcClient struct {
	cc *grpc.ClientConn
}

func NewPodInfoSvcClient(cc *grpc.ClientConn) PodInfoSvcClient {
	return &podInfoSvcClient{cc}
}

func (c *podInfoSvcClient) Get(ctx context.Context, in *PodInfoReq, opts ...grpc.CallOption) (*PodInfoRepl, error) {
	out := new(PodInfoRepl)
	err := c.cc.Invoke(ctx, "/proto.PodInfoSvc/Get", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PodInfoSvcServer is the server API for PodInfoSvc service.
type PodInfoSvcServer interface {
	Get(context.Context, *PodInfoReq) (*PodInfoRepl, error)
}

// UnimplementedPodInfoSvcServer can be embedded to have forward compatible implementations.
type UnimplementedPodInfoSvcServer struct {
}

func (*UnimplementedPodInfoSvcServer) Get(ctx context.Context, req *PodInfoReq) (*PodInfoRepl, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Get not implemented")
}

func RegisterPodInfoSvcServer(s *grpc.Server, srv PodInfoSvcServer) {
	s.RegisterService(&_PodInfoSvc_serviceDesc, srv)
}

func _PodInfoSvc_Get_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PodInfoReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PodInfoSvcServer).Get(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.PodInfoSvc/Get",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PodInfoSvcServer).Get(ctx, req.(*PodInfoReq))
	}
	return interceptor(ctx, in, info, handler)
}

var _PodInfoSvc_serviceDesc = grpc.ServiceDesc{
	ServiceName: "proto.PodInfoSvc",
	HandlerType: (*PodInfoSvcServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Get",
			Handler:    _PodInfoSvc_Get_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "podinfo_api.proto",
}
