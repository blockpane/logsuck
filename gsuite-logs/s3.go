package gsuitelogs

import (
	"bytes"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"log"
	"os"
	"strconv"
	"time"
)

// GetLastTS pulls a file from S3 that has the latest UNIX timestamp for retrieved logs.
// if it can't find the file, it will return 0
func GetLastTS() int64 {
	buff := aws.NewWriteAtBuffer([]byte{})
	downloader := s3manager.NewDownloader(s3Session)
	_, err := downloader.Download(buff, &s3.GetObjectInput{
		Bucket: aws.String(s3Details.Bucket),
		Key:    aws.String(s3Details.Key),
	})
	if err != nil {
		log.Printf("WARN: failed to download state file, %v", err)
		return 0
	}
	latest, err := strconv.Atoi(string(buff.Bytes()))
	if err != nil {
		log.Printf("WARN: failed to decode state file, %v", err)
		return 0
	}
	return int64(latest)
}

// SaveLastTS saves a text file with a unix timestamp representing the latest record we got
// into a S3 object.
func SaveLastTS(last int64) error {
	buff := bytes.NewBuffer([]byte(fmt.Sprintf("%d", last)))
	uploader := s3manager.NewUploader(s3Session)
	_, err := uploader.Upload(&s3manager.UploadInput{
		Body:   buff,
		Bucket: aws.String(s3Details.Bucket),
		//Key:                       aws.String(fmt.Sprintf("%s/%d.json", s3Details.SavePrefix, time.Now().UTC().Unix())),
		Key:                  aws.String(s3Details.Key),
		ServerSideEncryption: aws.String("AES256"),
	})
	return err
}

// SaveLog writes a logfile to S3, be sure to run this before SaveLastTS and skip writing the TS if this fails.
// the input should be a byte buffer containing rows of JSON text.
func SaveLog(result []byte) error {
	buff := bytes.NewReader(result)
	uploader := s3manager.NewUploader(s3Session)
	_, err := uploader.Upload(&s3manager.UploadInput{
		Body:                 buff,
		Bucket:               aws.String(s3Details.Bucket),
		Key:                  aws.String(fmt.Sprintf("%s/%d.json", s3Details.SavePrefix, time.Now().UTC().Unix())),
		ServerSideEncryption: aws.String("AES256"),
	})
	return err
}

// S3Details holds info for accessing S3
type S3Details struct {
	Region     string
	Bucket     string
	Key        string
	SavePrefix string
}

// NewS3Details reads environment variables, and if missing returns sensible defaults.
func NewS3Details() S3Details {
	details := S3Details{
		Region:     os.Getenv(`S3_REGION`),
		Bucket:     os.Getenv(`S3_BUCKET`),
		Key:        os.Getenv(`S3_KEY`),
		SavePrefix: os.Getenv(`S3_PREFIX`),
	}
	if details.Region == "" {
		details.Region = `us-east-1`
	}
	if details.Bucket == "" {
		log.Fatal("S3_BUCKET env var missing")
	}
	if details.Key == "" {
		details.Key = "gsuite-logs/latest.txt"
	}
	if details.SavePrefix == "" {
		details.SavePrefix = "gsuite-logs/logs/"
	}
	return details
}
