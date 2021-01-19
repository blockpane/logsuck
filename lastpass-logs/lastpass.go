package lastpasslogs

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

type LogRequest struct {
	Id      string            `json:"cid"`
	Secret  string            `json:"provhash"`
	Command string            `json:"cmd"`
	Data    map[string]string `json:"data"` //expects: { "from": "1970-01-01 00:00:00", "to": "1970-01-01 00:00:00" }
	Next    int               `json:"next,omitempty"`
}

// LastpassLog is the structure we return as marshalled json to stdout, it has different names/types than Orig
type LastpassLog struct {
	Ts        int64  `json:"ts"`
	Username  string `json:"username"`
	SrcIp     string `json:"src_ip"`
	EventName string `json:"event_name"`
	Detail    string `json:"description"`
}

type LastpassResponse struct {
	Status string                     `json:"status"`
	Next   int                        `json:"next"`
	Data   map[string]OrigLastpassLog `json:"data"`
}

// Parse splits logs into individual rows suitable for ingest
func (r LastpassResponse) Parse() (logs []LastpassLog) {
	for _, log := range r.Data {
		logs = append(logs, log.ToLog())
	}
	return
}

// OrigLastpassLog has different JSON names -- lastpass sends Studly Snake variables, we want plain snakes, this helps
type OrigLastpassLog struct {
	Timestamp string `json:"Time"`
	Username  string `json:"Username"`
	IpAddress string `json:"Ip_Address"`
	Action    string `json:"action"`
	Data      string `json:"Data"`
}

// ToLog converts a OrigLastpassLog to a LastpassLog
func (o OrigLastpassLog) ToLog() LastpassLog {
	t, err := time.ParseInLocation(lastpassFormat, o.Timestamp, lastpassTz)
	if err != nil {
		log.Println("Warning: couldn't parsing timestamp, using current time instead:", err)
		t = time.Now()
	}
	return LastpassLog{
		Ts:        t.Unix(),
		Username:  o.Username,
		SrcIp:     o.IpAddress,
		EventName: o.Action,
		Detail:    o.Data,
	}
}

// GetLogs returns the result of a reporting API query
func GetLogs(secret string, start time.Time) (results *LastpassResponse, err error) {
	from := start.In(lastpassTz).Format(lastpassFormat)
	to := time.Now().In(lastpassTz).Format(lastpassFormat)
	cid := getCid()
	postBody, err := json.Marshal(
		&LogRequest{
			Id:      cid,
			Secret:  secret,
			Command: "reporting",
			Data:    map[string]string{"from": from, "to": to},
		},
	)
	if err != nil {
		return
	}
	var tr = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	var client = &http.Client{
		Timeout:   time.Second * 10,
		Transport: tr,
	}
	resp, err := client.Post(lastpassApi, `application/json`, bytes.NewReader(postBody))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Body.Read: " + err.Error())
		return
	}
	err = json.Unmarshal(b, &results)
	if err != nil {
		log.Println("json.Unmarshal: " + err.Error())
		return
	}
	return
}

// getCid grabs the cid from ENV
func getCid() (cid string) {
	cid = os.Getenv(`CID`)
	if cid == "" {
		log.Fatal("No CID env var (client id) set.")
	}
	return
}
