package slacklogs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func GetLogs(slackRequest Request) (Response, error) {
	SlackResponse := Response{}
	body := []byte(fmt.Sprintf(
		`token=%s&before=%d&count=%d&page=%d`,
		Token,
		slackRequest.Before,
		slackRequest.Count,
		slackRequest.Page,
	))
	req, err := http.NewRequest("POST", ENDPOINT, bytes.NewBuffer(body))
	if err != nil {
		return SlackResponse, err
	}
	//req.Header.Set("Authorization", "Bearer "+Token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Close = true
	resp, err := Transport.RoundTrip(req)
	defer req.Body.Close()
	if err != nil {
		return SlackResponse, err
	}
	if resp.StatusCode != 200 {
		if resp.StatusCode == 429 {
			log.Printf("ERROR: Slack is rate limiting, sleeping for %d seconds\n", RATELIMITWAITSEC)
			time.Sleep(time.Second * RATELIMITWAITSEC)
		}
		return SlackResponse, errors.New(fmt.Sprintf("error getting logs got %d response", resp.StatusCode))
	}
	r, err := ioutil.ReadAll(resp.Body)
	if err != nil || len(r) == 0 {
		return SlackResponse, errors.New(fmt.Sprintf("could not read response body %v", err))
	}
	err = json.Unmarshal(r, &SlackResponse)
	if err != nil {
		return SlackResponse, err
	}
	if !SlackResponse.Ok {
		return SlackResponse, errors.New(SlackResponse.Error)
	}
	if len(SlackResponse.Logins) == 0 {
		return SlackResponse, errors.New("no results found")
	}
	Transport.CloseIdleConnections()
	time.Sleep(time.Duration(RATELIMITMS))
	return SlackResponse, nil
}
