package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	gsuitelogs "github.com/blockpane/logsuck/gsuite-logs"
)

func main() {
	lambda.Start(HandleRequest)
}

func HandleRequest() (msg string, err error) {
	startTs := gsuitelogs.GetLastTS()
	token, err := gsuitelogs.GetTokenSSM()
	if err != nil {
		return "could not fetch token from SSM", err
	}
	reportClient, err := token.NewReportClient()
	if err != nil {
		return "Could not authenticate", err
	}
	report, latest, err := gsuitelogs.GetLoginLogs(reportClient, startTs)
	if err != nil {
		return "Could not retrieve logs", err
	}
	if len(report) == 0 {
		return "no new logs", nil
	}
	err = gsuitelogs.SaveLog(report)
	if err != nil {
		return "Could not save logs", err
	}
	err = gsuitelogs.SaveLastTS(latest)
	if err != nil {
		return "Could not save latest timestamp", err
	}
	return "", nil
}
