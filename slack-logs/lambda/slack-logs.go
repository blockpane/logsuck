package main

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	slacklogs "github.com/blockpane/logsuck/slack-logs"
	"log"
)

func main() {
	//_ = handler()
	lambda.Start(handler)
}

func handler() error {
	newestLogin := int64(0)
	var err error
	slacklogs.Token, slacklogs.Last, err = slacklogs.GetSSMValues()
	if err != nil {
		log.Printf("Could not get SSM parameters: %v\n", err)
		return err
	}
	var done bool
	log.Println("looking for logs after:", slacklogs.Last.Unix())
outer:
	for {
		resp, err := slacklogs.GetLogs(slacklogs.Req)
		if err != nil {
			j, _ := json.MarshalIndent(resp, "", "  ")
			fmt.Println(string(j))
			return err
		}
		fmt.Printf("Results: %+v\n", resp.Paging)

		for _, login := range resp.Logins {
			if int64(login.DateLast) > newestLogin {
				newestLogin = int64(login.DateLast)
			}
			if int64(login.DateLast) <= slacklogs.Last.Unix() {
				fmt.Println("Found dup timestamp, all done.")
				done = true
				break outer
			} else {
				j, err := json.Marshal(login)
				if err != nil {
					log.Println(err)
				}
				fmt.Println(string(j))
			}
		}

		if slacklogs.Req.Page >= resp.Paging.Pages || done {
			break
		}
		slacklogs.Req.Next()
	}
	log.Println("saving updated ts:", newestLogin)
	if msg, err := slacklogs.SaveTime(newestLogin); err != nil {
		log.Printf("%s %v", msg, err)
		log.Fatal("Exiting. Could not update timestamp in SSM.")
	}
	return nil
}
