package info_test

import (
	"runtime/debug"

	"github.com/golang/mock/gomock"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/openshift/backplane-cli/pkg/info"
	infoBuildMock "github.com/openshift/backplane-cli/pkg/info/mocks"
)

var _ = Describe("Info", func() {
	var (
		mockCtrl         *gomock.Controller
		mockBuildService *infoBuildMock.MockBuildInfoService
		testBuildInfo    *debug.BuildInfo
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		mockBuildService = infoBuildMock.NewMockBuildInfoService(mockCtrl)
		info.DefaultBuildService = mockBuildService
		testBuildInfo = &debug.BuildInfo{
			Main: debug.Module{
				Version: "v1.2.3",
			},
		}
	})

	AfterEach(func() {
		mockCtrl.Finish()
	})

	Context("When getting build version", func() {
		It("Should return the pre-set Version is available", func() {
			mockBuildService.EXPECT().ReadBuildInfo().Return(testBuildInfo, true).Times(1)
			version := info.DefaultInfoService.GetVersion()
			Expect(version).To(Equal("1.2.3"))
		})
		/*It("Should return a version when go bulid info is available and there is no pre-set Version", func() {
			mockInfoService.EXPECT().GetVersion().Return("1.2.3").Times(1)
			version := info.DefaultInfoService.GetVersion()
			Expect(version).To(Equal("1.2.3"))
		})
		It("Should return an unknown when no way to determine version", func() {
			mockInfoService.EXPECT().GetVersion().Return("unknown").Times(1)
			version := info.DefaultInfoService.GetVersion()

			Expect(version).To(Equal("unknown"))
		})*/
	})
})
