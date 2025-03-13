package ocm

import (
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	ocmMock "github.com/openshift/backplane-cli/pkg/ocm/mocks"
)

var _ = Describe("OCM Wrapper test", func() {

	var (
		mockCtrl *gomock.Controller

		mockOcmInterface *ocmMock.MockOCMInterface
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())

		mockOcmInterface = ocmMock.NewMockOCMInterface(mockCtrl)
		DefaultOCMInterface = mockOcmInterface

	})

	AfterEach(func() {

	})

	Context("Test OCM Wrapper", func() {

		It("Should return trusted IPList", func() {
			ip1 := cmv1.NewTrustedIp().ID("100.10.10.10")
			ip2 := cmv1.NewTrustedIp().ID("200.20.20.20")
			expectedIpList, _ := cmv1.NewTrustedIpList().Items(ip1, ip2).Build()
			mockOcmInterface.EXPECT().GetTrustedIpList().Return(expectedIpList, nil).AnyTimes()
			IpList, err := DefaultOCMInterface.GetTrustedIpList()
			Expect(err).To(BeNil())
			Expect(len(IpList.Items())).Should(Equal(2))
		})
		It("Should not return errors for empty trusted IPList", func() {
			mockOcmInterface.EXPECT().GetTrustedIpList().Return(nil, nil).AnyTimes()
			_, err := DefaultOCMInterface.GetTrustedIpList()
			Expect(err).To(BeNil())
		})
	})
})
