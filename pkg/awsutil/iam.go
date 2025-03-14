package awsutil

import (
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const (
	PolicyVersion = "2012-10-17"
)

type PolicyDocument struct {
	Version   string            `json:"Version"`
	Statement []PolicyStatement `json:"Statement"`
}

type PolicyStatement struct {
	Sid       string            `json:"Sid"`        // Statement ID
	Effect    string            `json:"Effect"`     // Allow or Deny
	Action    []string          `json:"Action"`     // allowed or denied action
	Principal map[string]string `json:",omitempty"` // principal that is allowed or denied
	Resource  *string           `json:",omitempty"` // object or objects that the statement covers
	Condition *Condition        `json:",omitempty"` // conditions for when a policy is in effect
}

type Condition struct {
	NotIpAddress IpAddress `json:"NotIpAddress"`
}

type IpAddress struct {
	SourceIp []string `json:"aws:SourceIp"`
}

func NewPolicyDocument(version string, statements []PolicyStatement) PolicyDocument {
	return PolicyDocument{
		Version:   version,
		Statement: statements,
	}
}

func (p PolicyDocument) String() (string, error) {
	policyBytes, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return string(policyBytes), nil
}

func NewPolicyStatement(sid string, affect string, action []string) PolicyStatement {
	return PolicyStatement{
		Sid:    sid,
		Effect: affect,
		Action: action,
	}
}

func (ps PolicyStatement) AddResource(resource *string) PolicyStatement {
	ps.Resource = resource
	return ps
}

func (ps PolicyStatement) AddPrincipal(principle map[string]string) PolicyStatement {
	ps.Principal = principle
	return ps
}

func (ps PolicyStatement) AddCondition(condition *Condition) PolicyStatement {
	ps.Condition = condition
	return ps
}

func (p PolicyDocument) BuildPolicyWithRestrictedIp(ipAddress IpAddress) (PolicyDocument, error) {
	condition := Condition{
		NotIpAddress: ipAddress,
	}

	allAllow := NewPolicyStatement("AllowAll", "Allow", []string{"*"}).
		AddResource(aws.String("*")).
		AddCondition(nil)
	denyIp := NewPolicyStatement("DenyIp", "Deny", []string{"*"}).
		AddResource(aws.String("*")).
		AddCondition(&condition)
	p.Statement = []PolicyStatement{denyIp, allAllow}
	return p, nil
}
