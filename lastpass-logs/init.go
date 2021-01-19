package lastpasslogs

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	"time"
)

var (
	awsDetails = NewAwsDetails()
	awsSession = session.Must(
		session.NewSession(
			&aws.Config{
				Region: aws.String(awsDetails.Region),
			},
		),
	)
	paramStore     = ssm.New(awsSession, aws.NewConfig().WithRegion(awsDetails.Region))
	lastpassTz, _  = time.LoadLocation("America/Denver") // lastpass always expects US/Mountain in timestamps.
	lastpassFormat = `2006-01-02 15:04:05`
	lastpassApi    = `https://lastpass.com/enterpriseapi.php`
)
