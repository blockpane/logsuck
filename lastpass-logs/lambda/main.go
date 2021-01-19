package main

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	lastpasslogs "github.com/blockpane/logsuck/lastpass-logs"
	"log"
)

func main() {
	lambda.Start(handler)
}

func handler() (msg string, err error) {
	secret, last, err := lastpasslogs.GetSSMValues()
	var save bool
	latest := last.Unix()
	if err != nil {
		return "problem getting SSM parameters", err
	}
	newLogs, err := lastpasslogs.GetLogs(secret, last)
	if err != nil {
		return "problem getting logs from lastpass", err
	}
	for _, l := range newLogs.Parse() {
		if l.Ts > latest {
			save = true
			latest = l.Ts
		}
		j, err := json.Marshal(l)
		if err != nil {
			log.Println("problem unmarshalling log result", err)
			continue
		}
		fmt.Println(string(j))
	}
	if save {
		msg, err = lastpasslogs.SaveTime(latest)
	}
	return
}
