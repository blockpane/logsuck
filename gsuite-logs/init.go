package gsuitelogs

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	admin "google.golang.org/api/admin/reports/v1"
)

var (
	awsDetails = NewAwsDetails()
	s3Details  = NewS3Details()
	awsSession = session.Must(
		session.NewSession(
			&aws.Config{
				Region: aws.String(awsDetails.Region),
			},
		),
	)
	s3Session = session.Must(
		session.NewSession(
			&aws.Config{
				Region: aws.String(s3Details.Region),
			},
		),
	)
	paramStore = ssm.New(awsSession, aws.NewConfig().WithRegion(awsDetails.Region))
	pages      = make([]*admin.Activity, 0)
)
