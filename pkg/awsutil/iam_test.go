package awsutil

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AWS IAM Util tests", func() {

	BeforeEach(func() {

	})

	AfterEach(func() {

	})

	Context("Test IAM policy document", func() {

		It("Should return string policy", func() {
			statements := []PolicyStatement{
				{
					Sid:       "AllowAll",
					Effect:    "Allow",
					Action:    []string{"*"},
					Resource:  aws.String("*"),
					Condition: nil,
				},
			}
			expectedRawPolicy := `{"Version":"2012-10-17","Statement":[{"Sid":"AllowAll","Effect":"Allow","Action":["*"],"Resource":"*"}]}`

			policy := NewPolicyDocument(PolicyVersion, statements)
			rawPolicy, err := policy.String()
			Expect(err).To(BeNil())
			Expect(rawPolicy).NotTo(BeNil())
			Expect(rawPolicy).To(Equal(expectedRawPolicy))
		})

		It("Should return All Allow policy", func() {

			statement := NewPolicyStatement("AllowAll", "Allow", []string{"*"}).
				AddResource(aws.String("*")).
				AddCondition(nil)

			expectedRawPolicy := `{"Version":"2012-10-17","Statement":[{"Sid":"AllowAll","Effect":"Allow","Action":["*"],"Resource":"*"}]}`

			policy := NewPolicyDocument(PolicyVersion, []PolicyStatement{statement})
			rawPolicy, err := policy.String()
			Expect(err).To(BeNil())
			Expect(statement).NotTo(BeNil())
			Expect(rawPolicy).To(Equal(expectedRawPolicy))
		})
		It("Should return All Deny Policy", func() {

			statement := NewPolicyStatement("AllowDeny", "Deny", []string{"*"}).
				AddResource(aws.String("*")).
				AddCondition(nil)

			expectedRawPolicy := `{"Version":"2012-10-17","Statement":[{"Sid":"AllowDeny","Effect":"Deny","Action":["*"],"Resource":"*"}]}`

			policy := NewPolicyDocument(PolicyVersion, []PolicyStatement{statement})
			rawPolicy, err := policy.String()
			Expect(err).To(BeNil())
			Expect(statement).NotTo(BeNil())
			Expect(rawPolicy).To(Equal(expectedRawPolicy))
		})
		It("Should return restricted IP policy", func() {

			expectedRawPolicy := `{"Version":"2012-10-17","Statement":[{"Sid":"DenyIp","Effect":"Deny","Action":["*"],"Resource":"*",` +
				`"Condition":{"NotIpAddress":{"aws:SourceIp":["100.10.10.10"]}}},{"Sid":"AllowAll","Effect":"Allow","Action":["*"],"Resource":"*"}]}`
			sourceIpList := []string{"100.10.10.10"}

			ipAddress := IpAddress{SourceIp: sourceIpList}
			policy := NewPolicyDocument(PolicyVersion, []PolicyStatement{})

			policy, err := policy.BuildPolicyWithRestrictedIp(ipAddress)
			Expect(err).To(BeNil())
			rawPolicy, err := policy.String()
			fmt.Print(rawPolicy)
			Expect(err).To(BeNil())
			Expect(rawPolicy).To(Equal(expectedRawPolicy))
		})
	})
})
