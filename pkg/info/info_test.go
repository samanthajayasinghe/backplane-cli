package info_test

import (
	"runtime/debug"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/openshift/backplane-cli/pkg/info"
)

// Mock implementation of debug.ReadBuildInfo
func mockReadBuildInfoAvail() (*debug.BuildInfo, bool) {
	return &debug.BuildInfo{
		Main: debug.Module{
			Version: "v1.2.3",
		},
	}, true
}

// Mock implementation of debug.ReadBuildInfo
func mockReadBuildInfoNotAvail() (*debug.BuildInfo, bool) {
	return nil, false
}

var _ = Describe("Info", func() {
	Context("When getting build version", func() {
		It("Should return the pre-set Version is available", func() {
			info.Version = "whatever"

			version := info.DefaultInfoService.GetVersion()
			Expect(version).To(Equal("whatever"))
		})
		It("Should return a version when go bulid info is available and there is no pre-set Version", func() {
			info.Version = ""
			info.ReadBuildInfo = mockReadBuildInfoAvail

			version := info.DefaultInfoService.GetVersion()
			Expect(version).To(Equal("1.2.3"))
		})
		It("Should return an unknown when no way to determine version", func() {
			info.Version = ""
			info.ReadBuildInfo = mockReadBuildInfoNotAvail

			version := info.DefaultInfoService.GetVersion()
			Expect(version).To(Equal("unknown"))
		})
	})
})
