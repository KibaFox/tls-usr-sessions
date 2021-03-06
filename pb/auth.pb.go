// Code generated by protoc-gen-go. DO NOT EDIT.
// source: auth.proto

package pb

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
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
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type LoginRequest struct {
	Username string `protobuf:"bytes,1,opt,name=username,proto3" json:"username,omitempty"`
	Password string `protobuf:"bytes,2,opt,name=password,proto3" json:"password,omitempty"`
	// CSR is the certificate signing request presented by the client to sign if
	// the login succeds.
	Csr                  string   `protobuf:"bytes,3,opt,name=csr,proto3" json:"csr,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LoginRequest) Reset()         { *m = LoginRequest{} }
func (m *LoginRequest) String() string { return proto.CompactTextString(m) }
func (*LoginRequest) ProtoMessage()    {}
func (*LoginRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_8bbd6f3875b0e874, []int{0}
}

func (m *LoginRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LoginRequest.Unmarshal(m, b)
}
func (m *LoginRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LoginRequest.Marshal(b, m, deterministic)
}
func (m *LoginRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LoginRequest.Merge(m, src)
}
func (m *LoginRequest) XXX_Size() int {
	return xxx_messageInfo_LoginRequest.Size(m)
}
func (m *LoginRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_LoginRequest.DiscardUnknown(m)
}

var xxx_messageInfo_LoginRequest proto.InternalMessageInfo

func (m *LoginRequest) GetUsername() string {
	if m != nil {
		return m.Username
	}
	return ""
}

func (m *LoginRequest) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

func (m *LoginRequest) GetCsr() string {
	if m != nil {
		return m.Csr
	}
	return ""
}

type LoginResponse struct {
	// Cert is the signed certificate that the client must use for the
	// authenticated user session in PEM format.
	Cert string `protobuf:"bytes,1,opt,name=cert,proto3" json:"cert,omitempty"`
	// Anchors contains the root anchors certificate(s) for the user session trust
	// chain in PEM format.
	Anchors              string   `protobuf:"bytes,2,opt,name=anchors,proto3" json:"anchors,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LoginResponse) Reset()         { *m = LoginResponse{} }
func (m *LoginResponse) String() string { return proto.CompactTextString(m) }
func (*LoginResponse) ProtoMessage()    {}
func (*LoginResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_8bbd6f3875b0e874, []int{1}
}

func (m *LoginResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LoginResponse.Unmarshal(m, b)
}
func (m *LoginResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LoginResponse.Marshal(b, m, deterministic)
}
func (m *LoginResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LoginResponse.Merge(m, src)
}
func (m *LoginResponse) XXX_Size() int {
	return xxx_messageInfo_LoginResponse.Size(m)
}
func (m *LoginResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_LoginResponse.DiscardUnknown(m)
}

var xxx_messageInfo_LoginResponse proto.InternalMessageInfo

func (m *LoginResponse) GetCert() string {
	if m != nil {
		return m.Cert
	}
	return ""
}

func (m *LoginResponse) GetAnchors() string {
	if m != nil {
		return m.Anchors
	}
	return ""
}

func init() {
	proto.RegisterType((*LoginRequest)(nil), "pb.LoginRequest")
	proto.RegisterType((*LoginResponse)(nil), "pb.LoginResponse")
}

func init() { proto.RegisterFile("auth.proto", fileDescriptor_8bbd6f3875b0e874) }

var fileDescriptor_8bbd6f3875b0e874 = []byte{
	// 177 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x4c, 0x8f, 0x3b, 0x0f, 0xc2, 0x20,
	0x14, 0x85, 0xed, 0xc3, 0xd7, 0x8d, 0x26, 0xf5, 0x4e, 0xa4, 0x93, 0xe9, 0xe4, 0xc4, 0xa0, 0x89,
	0x9b, 0x83, 0xbb, 0x53, 0x27, 0x57, 0x5a, 0x89, 0x75, 0x10, 0x90, 0x0b, 0xf1, 0xef, 0x9b, 0x52,
	0x6a, 0xba, 0x9d, 0xef, 0x9c, 0xe4, 0x83, 0x0b, 0x20, 0xbc, 0xeb, 0xb8, 0xb1, 0xda, 0x69, 0x4c,
	0x4d, 0x53, 0xdd, 0x61, 0x73, 0xd3, 0xcf, 0x97, 0xaa, 0xe5, 0xc7, 0x4b, 0x72, 0x58, 0xc2, 0xca,
	0x93, 0xb4, 0x4a, 0xbc, 0x25, 0x4b, 0xf6, 0xc9, 0x61, 0x5d, 0xff, 0xb9, 0xdf, 0x8c, 0x20, 0xfa,
	0x6a, 0xfb, 0x60, 0xe9, 0xb0, 0x8d, 0x8c, 0x05, 0x64, 0x2d, 0x59, 0x96, 0x85, 0xba, 0x8f, 0xd5,
	0x05, 0xb6, 0xd1, 0x4c, 0x46, 0x2b, 0x92, 0x88, 0x90, 0xb7, 0xd2, 0xba, 0xa8, 0x0d, 0x19, 0x19,
	0x2c, 0x85, 0x6a, 0x3b, 0x6d, 0x29, 0x1a, 0x47, 0x3c, 0x9e, 0x21, 0xbf, 0x7a, 0xd7, 0x21, 0x87,
	0x79, 0xd0, 0x60, 0xc1, 0x4d, 0xc3, 0xa7, 0x7f, 0x2d, 0x77, 0x93, 0x66, 0x78, 0xa3, 0x9a, 0x35,
	0x8b, 0x70, 0xdb, 0xe9, 0x17, 0x00, 0x00, 0xff, 0xff, 0x67, 0x05, 0x15, 0xb7, 0xe9, 0x00, 0x00,
	0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// AuthClient is the client API for Auth service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type AuthClient interface {
	Login(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*LoginResponse, error)
}

type authClient struct {
	cc *grpc.ClientConn
}

func NewAuthClient(cc *grpc.ClientConn) AuthClient {
	return &authClient{cc}
}

func (c *authClient) Login(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*LoginResponse, error) {
	out := new(LoginResponse)
	err := c.cc.Invoke(ctx, "/pb.Auth/Login", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuthServer is the server API for Auth service.
type AuthServer interface {
	Login(context.Context, *LoginRequest) (*LoginResponse, error)
}

// UnimplementedAuthServer can be embedded to have forward compatible implementations.
type UnimplementedAuthServer struct {
}

func (*UnimplementedAuthServer) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Login not implemented")
}

func RegisterAuthServer(s *grpc.Server, srv AuthServer) {
	s.RegisterService(&_Auth_serviceDesc, srv)
}

func _Auth_Login_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServer).Login(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.Auth/Login",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServer).Login(ctx, req.(*LoginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Auth_serviceDesc = grpc.ServiceDesc{
	ServiceName: "pb.Auth",
	HandlerType: (*AuthServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Login",
			Handler:    _Auth_Login_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "auth.proto",
}
