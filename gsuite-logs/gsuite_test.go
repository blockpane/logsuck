package gsuitelogs

import (
	"testing"
	"time"
)

func TestGetLoginLogs(t *testing.T) {
	creds, err := GetTokenSSM()
	if err != nil {
		t.Errorf("could not get oauth2 token: %v\n", err)
	}
	gClient, err := creds.NewReportClient()
	if err != nil {
		t.Errorf("could not get google reporting api session: %v\n", err)
	}
	results, latest, err := GetLoginLogs(gClient, time.Now().Add(-72*time.Hour).UTC().Unix())
	if err != nil {
		t.Errorf("could not retrieve logs: %v\n", err)
	} else if len(results) == 0 {
		t.Error("got an empty result from google report api")
	} else if latest == 0 {
		t.Error("got a 0 timestamp from google report api for the latest record")
	}
	//fmt.Println(string(results))
	s3Details.SavePrefix = `gsuite-logs/tests/`
	err = SaveLog(results)
	if err != nil {
		t.Error("could not write log")
	}
}
