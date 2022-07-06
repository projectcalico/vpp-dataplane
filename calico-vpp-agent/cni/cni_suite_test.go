package cni_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestCni(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cni Suite")
}
