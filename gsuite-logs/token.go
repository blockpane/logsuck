package gsuitelogs

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/reports/v1"
	"log"
	"os"
)

// OauthConfigAndToken holds both the oauth2 config and token for persistence, this is marshalled and stored in
// parameter store.
type OauthConfigAndToken struct {
	Config *oauth2.Config
	Token  *oauth2.Token
}

// GetTokenSSM retrieves a saved oauth2.Token from AWS SSM/Parameter store.
func GetTokenSSM() (OauthConfigAndToken, error) {
	tokenParam, err := paramStore.GetParameter(
		&ssm.GetParameterInput{
			Name:           aws.String(awsDetails.TokenParameter),
			WithDecryption: aws.Bool(true),
		},
	)
	if err != nil {
		return OauthConfigAndToken{}, err
	}
	config := OauthConfigAndToken{}
	err = json.Unmarshal([]byte(*tokenParam.Parameter.Value), &config.Token)
	if err != nil {
		return OauthConfigAndToken{}, err
	}
	configParam, err := paramStore.GetParameter(
		&ssm.GetParameterInput{
			Name:           aws.String(awsDetails.ConfigParameter),
			WithDecryption: aws.Bool(true),
		},
	)
	if err != nil {
		return OauthConfigAndToken{}, err
	}
	config.Config, err = google.ConfigFromJSON([]byte(*configParam.Parameter.Value), admin.AdminReportsAuditReadonlyScope)
	if err != nil {
		return OauthConfigAndToken{}, err
	}
	return config, nil
}

// Refresh checks the expiration of the token so we know if we should save the refreshed token to parameter store
// if true, the refreshed token is saved.
func (o *OauthConfigAndToken) Refresh() error {
	tokenSource := o.Config.TokenSource(oauth2.NoContext, o.Token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return err
	}
	if newToken.AccessToken != o.Token.AccessToken {
		o.Token = newToken
		err := o.Save()
		if err != nil {
			log.Println("ERROR: could not save token")
			return err
		}
		log.Println("INFO: Saved new token")
	}
	return nil
}

// NewReportClient gets a google admin reports session using the token. If the token is stale
// it will update the SSM Parameter.
func (o *OauthConfigAndToken) NewReportClient() (service *admin.Service, err error) {
	err = o.Refresh()
	if err != nil {
		return
	}
	client := o.Config.Client(context.Background(), o.Token)
	service, err = admin.New(client)
	return
}

// Save persists the token to parameter store after an update
func (o OauthConfigAndToken) Save() error {
	j, err := json.Marshal(o.Token)
	if err != nil {
		return err
	} else if len(j) == 0 {
		return errors.New("refusing to save empty token")
	}
	_, err = paramStore.PutParameter(
		&ssm.PutParameterInput{
			Description: aws.String(`gsuite logs oauth2 token`),
			Name:        aws.String(awsDetails.TokenParameter),
			Overwrite:   aws.Bool(true),
			Type:        aws.String(`SecureString`),
			Value:       aws.String(string(j)),
		},
	)
	return err
}

// AwsDetails holds info for accessing SSM parameter store
type AwsDetails struct {
	Region          string `json:"region"`
	TokenParameter  string `json:"token_parameter"`
	ConfigParameter string `json:"config_parameter"`
}

// NewAwsDetails reads environment variables, and if missing returns sensible defaults.
func NewAwsDetails() AwsDetails {
	details := AwsDetails{
		Region:          os.Getenv(`REGION`),
		ConfigParameter: os.Getenv(`CONFIG_PARAMETER`),
		TokenParameter:  os.Getenv(`TOKEN_PARAMETER`),
	}
	if details.Region == "" {
		details.Region = `us-east-1`
	}
	if details.TokenParameter == "" {
		details.TokenParameter = "gsuite-logs-token"
	}
	if details.ConfigParameter == "" {
		details.ConfigParameter = "gsuite-logs-config"
	}
	return details
}
