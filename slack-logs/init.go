package slacklogs

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	"net"
	"net/http"
	"time"
)

const (
	ENDPOINT         = `https://slack.com/api/team.accessLogs`
	RATELIMITMS      = 50
	RATELIMITWAITSEC = 30
)

var (
	//Token     string
	Req       = NewRequest()
	Transport = &http.Transport{
		ResponseHeaderTimeout: time.Second * 15,
		DisableKeepAlives:     true,
	}
	awsDetails = NewAwsDetails()
	awsSession = session.Must(
		session.NewSession(
			&aws.Config{
				Region: aws.String(awsDetails.Region),
			},
		),
	)
	paramStore = ssm.New(awsSession, aws.NewConfig().WithRegion(awsDetails.Region))
	Token      string
	Last       time.Time
)

type Request struct {
	Token  string `json:"token"`
	Before int64  `json:"before"`
	Count  int    `json:"count"`
	Page   int    `json:"page"`
}

func NewRequest() Request {
	return Request{
		Before: time.Now().UTC().Unix(),
		Count:  100,
		Page:   1,
	}
}

func (r *Request) Next() {
	r.Page = r.Page + 1
}

type AccessLog struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	DateFirst int    `json:"date_first"`
	DateLast  int    `json:"date_last"`
	Count     int    `json:"count"`
	IP        net.IP `json:"ip"`
	UserAgent string `json:"user_agent"`
	ISP       string `json:"isp"`
	Country   string `json:"country"`
	Region    string `json:"region"`
}

type Page struct {
	Count int `json:"count"`
	Total int `json:"total"`
	Page  int `json:"page"`
	Pages int `json:"pages"`
}

// More tells us to keep going.
func (p Page) More() bool {
	if p.Total == 0 {
		return false
	}
	return true
}

type Response struct {
	Ok     bool        `json:"ok"`
	Error  string      `json:"error"`
	Logins []AccessLog `json:"logins"`
	Paging Page        `json:"paging"`
}
