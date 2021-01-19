package slacklogs

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"log"
	"os"
	"strconv"
	"time"
)

// GetTokenSSM retrieves a saved auth Token from AWS SSM/Parameter store.
func GetSSMValues() (secret string, last time.Time, err error) {
	tokenParam, err := paramStore.GetParameter(
		&ssm.GetParameterInput{
			Name:           aws.String(awsDetails.TokenParameter),
			WithDecryption: aws.Bool(true),
		},
	)
	if err != nil {
		return
	}
	secret = aws.StringValue(tokenParam.Parameter.Value)
	timeParam, err := paramStore.GetParameter(
		&ssm.GetParameterInput{
			Name: aws.String(awsDetails.TimeParameter),
		},
	)
	if err != nil {
		return
	}
	ts := aws.StringValue(timeParam.Parameter.Value)
	i, err := strconv.Atoi(ts)
	if err != nil {
		log.Println("Error converting timestamp to integer, returning 0. ", err)
		i = 0
	}
	return secret, time.Unix(int64(i), 0), nil
}

// SaveTime persists the timestamp to parameter store after an update
func SaveTime(t int64) (msg string, err error) {
	_, err = paramStore.PutParameter(
		&ssm.PutParameterInput{
			Description: aws.String(`slack lastest log timestamp`),
			Name:        aws.String(awsDetails.TimeParameter),
			Overwrite:   aws.Bool(true),
			Type:        aws.String(`String`),
			Value:       aws.String(strconv.Itoa(int(t))),
		},
	)
	if err != nil {
		msg = "problem saving latest timestamp to SSM"
	}
	return
}

// AwsDetails holds info for accessing SSM parameter store
type AwsDetails struct {
	Region         string `json:"region"`
	TokenParameter string `json:"token_parameter"`
	TimeParameter  string `json:"time_parameter"`
}

// NewAwsDetails reads environment variables, and if missing returns sensible defaults.
func NewAwsDetails() AwsDetails {
	details := AwsDetails{
		Region:         os.Getenv(`REGION`),
		TokenParameter: os.Getenv(`TOKEN_PARAMETER`),
		TimeParameter:  os.Getenv(`TIMESTAMP_PARAMETER`),
	}
	if details.Region == "" {
		details.Region = `us-east-1`
	}
	if details.TokenParameter == "" {
		details.TokenParameter = "slack"
	}
	if details.TimeParameter == "" {
		details.TimeParameter = "slack-timestamp"
	}
	return details
}
