//go:generate protoc -I=. --gogo_out=plugins=grpc:. ./podinfo_api.proto

package grpcsrv

// The grpcsrv package defines an API between the CNI plugin's gRPC server
// and a process requesting information about a specific pod. Proto file defines
// information gRPC server returns upon a request.

// Use go generate to regenerate the go file.
