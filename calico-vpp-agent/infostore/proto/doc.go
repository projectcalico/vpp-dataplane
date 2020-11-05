//go:generate protoc -I=. --gogo_out=plugins=grpc:. ./podinfo_api.proto

package proto

// The proto package defines an API between the CNI plugin's infostore gRPC server
// and a process requesting information about a specific pod. Proto file defines
// information gRPC server returns upon a request.

// Use go generate to regenerate the go file.
