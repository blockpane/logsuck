package gsuitelogs

import (
	"context"
	"encoding/json"
	admin "google.golang.org/api/admin/reports/v1"
	"log"
	"time"
)

// FlattenedLog is the struct for JSON log output, it intentionally omits nested objects for easier to process logs.
type FlattenedLog struct {
	Username             string   `json:"username,omitempty"`
	ProfileID            string   `json:"profile_id,omitempty"`
	Kind                 string   `json:"kind,omitempty"`
	SourceIP             string   `json:"src_ip,omitempty"`
	ETag                 string   `json:"e_tag,omitempty"`
	EventName            string   `json:"event_name,omitempty"`
	LoginType            string   `json:"login_type,omitempty"`
	LoginFailureType     []string `json:"login_failure_type,omitempty"`
	LoginChallengeMethod []string `json:"login_challenge_method,omitempty"`
	IsSecondFactor       bool     `json:"is_second_factor,omitempty"`
	LoginChallengeStatus string   `json:"login_challenge_status,omitempty"`
	AffectedEmailAddress string   `json:"affected_email_address,omitempty"`
	IsSuspicious         bool     `json:"is_suspicious,omitempty"`
	Time                 string   `json:"time"`
	LogType              string   `json:"log_type"`
	LoginTimeStamp       int64    `json:"login_time_stamp,omitempty"`
}

// FlattenLog manipulates the format of the log message to flatten the JSON structure so it's more compatible
// with tools like Kibana
func FlattenLog(a *admin.Activity) FlattenedLog {
	l := FlattenedLog{
		Username:  a.Actor.Email,
		ProfileID: a.Actor.ProfileId,
		Kind:      a.Kind,
		SourceIP:  a.IpAddress,
		ETag:      a.Etag,
		Time:      a.Id.Time,
		LogType:   a.Id.ApplicationName,
	}
	for _, event := range a.Events {
		l.EventName = event.Name
		for _, e := range event.Parameters {
			switch e.Name {
			case "login_type":
				l.LoginType = e.Value
			case "login_challenge_method":
				if len(e.MultiValue) > 0 {
					l.LoginChallengeMethod = e.MultiValue
				} else if e.Value != "" {
					l.LoginChallengeMethod = []string{e.Value}
				}
			case "is_suspicious":
				l.IsSuspicious = e.BoolValue
			case "login_challenge_status":
				l.LoginChallengeStatus = e.Value
			case "is_second_factor":
				l.IsSecondFactor = e.BoolValue
			case "login_failure_type":
				if len(e.MultiValue) > 0 {
					l.LoginFailureType = e.MultiValue
				} else if e.Value != "" {
					l.LoginFailureType = []string{e.Value}
				}
			case "affected_email_address":
				l.AffectedEmailAddress = e.Value
			case "login_timestamp":
				l.LoginTimeStamp = e.IntValue
			}
		}

	}
	return l
}

// pagesCallback handles collating events into the pages slice from admin.ActivitiesListCall.Pages
func pagesCallback(report *admin.Activities) error {
	for _, i := range report.Items {
		pages = append(pages, i)
	}
	return nil
}

// GetLoginLogs fetches all the login data from the admin reports api, that occurred after the date specified.
// The returned byte slice is marshalled json
func GetLoginLogs(service *admin.Service, startTime int64) (results []byte, latestTs int64, err error) {
	results = make([]byte, 0)
	start := time.Unix(startTime+int64(1), 0).UTC()
	latest := start
	log.Println("Searching for logs after", start.Format(time.RFC3339))
	a := service.Activities.List("all", "login")
	err = a.StartTime(start.Format(time.RFC3339Nano)).Pages(context.Background(), pagesCallback)
	if err != nil {
		log.Printf("ERROR: when retrieving logs, %v\n", err)
		return nil, latest.Unix(), err
	}
	var skipped int
	for _, r := range pages {
		t, err := time.Parse(time.RFC3339, r.Id.Time)
		if err != nil {
			log.Println("ERROR couldn't parse timestamp into RFC3339 format:", r.Id.Time)
			continue
		} else if t.After(latest) {
			latest = t
		} else if t.Before(start) {
			// some sort of bug, sometimes google is not honoring the timestamp?
			skipped += 1
			continue
		}
		flat := FlattenLog(r)
		j, _ := json.Marshal(flat)
		results = append(results, j...)
		results = append(results, '\n')
	}
	log.Printf("got %d log entries, skipped %d\n", len(pages), skipped)
	return results, latest.Unix(), nil
}
