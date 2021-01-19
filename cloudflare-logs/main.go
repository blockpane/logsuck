package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	endpoint = "https://api.cloudflare.com/client/v4/graphql/"
	q        = `query ListFirewallEvents($zoneTag: string, $filter: FirewallEventsAdaptiveFilter_InputObject) {
          viewer {
          zones(filter: { zoneTag: $zoneTag }) {
            firewallEventsAdaptive(
              filter: $filter
              limit: 100
              orderBy: [datetime_ASC]
            ) {
              action
              clientASNDescription
              clientAsn
              clientCountryName
              clientIP
              clientRequestHTTPHost
              clientRequestHTTPMethodName
              clientRequestHTTPProtocol
              clientRequestPath
              clientRequestQuery
              datetime
              rayName
              ruleId
              source
              userAgent
            }
          }
        }
      }`
)

type GraphQuery struct {
	Query     string `json:"query"`
	Variables struct {
		ZoneTag string `json:"zoneTag"`
		Filter  struct {
			DatetimeGeq string `json:"datetime_geq"`
			DatetimeLeq string `json:"datetime_leq"`
		} `json:"filter"`
	} `json:"variables"`
}

func NewQuery(start time.Time, end time.Time, zone string) GraphQuery {
	gq := GraphQuery{Query: q}
	gq.Variables.Filter.DatetimeGeq = start.UTC().Format("2006-01-02T15:04:05Z")
	gq.Variables.Filter.DatetimeLeq = end.UTC().Format("2006-01-02T15:04:05Z")
	gq.Variables.ZoneTag = zone
	return gq
}

type Event struct {
	Action    string    `json:"action"`
	AsnDesc   string    `json:"clientASNDescription"`
	Asn       string    `json:"clientAsn"`
	Country   string    `json:"clientCountryName"`
	Ip        net.IP    `json:"clientIP"`
	Host      string    `json:"clientRequestHTTPHost"`
	Method    string    `json:"clientRequestHTTPMethodName"`
	Proto     string    `json:"clientRequestHTTPProtocol"`
	Path      string    `json:"clientRequestPath"`
	Query     string    `json:"clientRequestQuery"`
	Date      time.Time `json:"datetime"`
	Ray       string    `json:"rayName"`
	Rule      string    `json:"ruleId"`
	Source    string    `json:"source"`
	UserAgent string    `json:"userAgent"`
}

type Response struct {
	Data struct {
		Viewer struct {
			Zones []struct {
				Events []Event `json:"firewallEventsAdaptive"`
			} `json:"zones"`
		} `json:"viewer"`
	} `json:"data"`
}

func GetLogs() error {
	var (
		authEmail, authKey, zoneId string
		last                       = time.Now()
		err                        error
	)

	authEmail, authKey, zoneId, last, err = getSettings()
	if err != nil {
		log.Println(err)
		return err
	}

	client := &http.Client{Timeout: time.Second * 10}
	for {
		until := last.Add(86399 * time.Second) // 86400 max, take one away to be safe.
		if until.After(time.Now()) {
			until = time.Now()
		}
		if last.Add(time.Second).After(until) {
			return saveTimeStamp(last)
		}

		gq := NewQuery(last.Add(time.Second), until, zoneId)
		query, err := json.Marshal(&gq)
		if err != nil {
			log.Println(err)
			return err
		}

		req, err := http.NewRequest("POST", endpoint, bytes.NewReader(query))
		if err != nil {
			log.Println(err)
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Auth-Email", authEmail)
		req.Header.Set("X-Auth-Key", authKey)

		resp, err := client.Do(req)
		if err != nil {
			log.Println(err)
			return err
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println(err)
			return err
		}
		resp.Body.Close()

		response := &Response{}
		err = json.Unmarshal(body, response)
		if err != nil {
			fmt.Println(string(body))
			log.Println(err)
			return err
		}

		if response.Data.Viewer.Zones == nil || len(response.Data.Viewer.Zones) == 0 || len(response.Data.Viewer.Zones[0].Events) == 0 {
			return saveTimeStamp(last)
		}

		for _, evt := range response.Data.Viewer.Zones[0].Events {
			last = evt.Date
			j, _ := json.Marshal(evt)
			fmt.Println(string(j))
		}
	}
}

func getSettings() (email string, key string, zone string, last time.Time, err error) {
	log.SetFlags(log.Lshortfile | log.LstdFlags | log.LUTC)
	ssmEmail := os.Getenv("SSM_EMAIL")
	ssmKey := os.Getenv("SSM_KEY")
	ssmZone := os.Getenv("SSM_ZONE")
	ssmTime := os.Getenv("SSM_TIMESTAMP")

	switch "" {
	case os.Getenv("AWS_REGION"):
		err = errors.New("is this running in Lambda? AWS_REGION env var missing")
		return
	case ssmEmail, ssmKey, ssmZone, ssmTime:
		//log.Println("warning: did not get SSM_EMAIL, SSM_KEY, SSM_TIMESTAMP or SSM_ZONE. Using default values of /cloudflare/(email|key|last|zone)")
		ssmEmail = "/cloudflare/email"
		ssmKey = "/cloudflare/key"
		ssmZone = "/cloudflare/zone"
		ssmTime = "/cloudflare/last"
	}

	awsSession := session.Must(
		session.NewSession(
			&aws.Config{
				Region: aws.String(os.Getenv("AWS_REGION")),
			},
		),
	)
	ps := ssm.New(awsSession)

	var emailOut, keyOut, zoneOut, timeOut *ssm.GetParameterOutput
	emailOut, err = ps.GetParameter(&ssm.GetParameterInput{
		Name:           aws.String(ssmEmail),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		log.Println(err)
		return
	}
	keyOut, err = ps.GetParameter(&ssm.GetParameterInput{
		Name:           aws.String(ssmKey),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		log.Println(err)
		return
	}
	zoneOut, err = ps.GetParameter(&ssm.GetParameterInput{
		Name:           aws.String(ssmZone),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		log.Println(err)
		return
	}
	timeOut, err = ps.GetParameter(&ssm.GetParameterInput{
		Name:           aws.String(ssmTime),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		log.Println(err)
		return
	}

	email = aws.StringValue(emailOut.Parameter.Value)
	key = aws.StringValue(keyOut.Parameter.Value)
	zone = aws.StringValue(zoneOut.Parameter.Value)

	switch "" {
	case email, key, zone:
		err = errors.New("one or more required parameters were empty")
		return
	}

	t := aws.StringValue(timeOut.Parameter.Value)
	if t != "" {
		last, err = time.Parse(time.RFC3339, t)
		return
	}

	last = time.Now()
	log.Println("warning: could not get last time from SSM, defaulting to now")
	return
}

func saveTimeStamp(t time.Time) error {
	ssmTime := os.Getenv("SSM_TIMESTAMP")
	if ssmTime == "" {
		ssmTime = "/cloudflare/last"
	}

	awsSession := session.Must(
		session.NewSession(
			&aws.Config{
				Region: aws.String(os.Getenv("AWS_REGION")),
			},
		),
	)
	ps := ssm.New(awsSession)
	_, err := ps.PutParameter(&ssm.PutParameterInput{
		Name:      aws.String(ssmTime),
		Overwrite: aws.Bool(true),
		Type:      aws.String("String"),
		Value:     aws.String(t.UTC().Format(time.RFC3339)),
	})

	return err
}

func main() {
	lambda.Start(GetLogs)
}
