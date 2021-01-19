package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	guarddutylogs "github.com/blockpane/logsuck/guardduty-logs"
)

func main() {
	lambda.Start(HandleRequest)
}

func HandleRequest(ctx context.Context, event events.CloudWatchEvent) (msg string, err error) {
	gd, err := guarddutylogs.ParseEvent(&event.Detail)
	if err != nil {
		return "couldn't decode Finding", err
	}
	logs, err := guarddutylogs.NewLogs(gd)
	if err != nil {
		return "couldn't build logs slice", err
	}
	for _, log := range logs {
		j, _ := json.Marshal(log)
		fmt.Println(string(j))
	}
	return "", nil

}
