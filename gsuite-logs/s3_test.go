package gsuitelogs

import (
	"testing"
	"time"
)

func TestSaveLastTS(t *testing.T) {
	s3Details.Key = `gsuite-logs/tests/latest.txt`
	err := SaveLastTS(time.Now().Unix())
	if err != nil {
		t.Errorf("could not save state file: %v\n", err)
	}
}

func TestGetLastTS(t *testing.T) {
	s3Details.Key = `gsuite-logs/tests/latest.txt`
	last := GetLastTS()
	if last == 0 {
		t.Error("could not read last timestamp")
	}
}

func TestSaveLog(t *testing.T) {
	s3Details.SavePrefix = `gsuite-logs/tests/`
	err := SaveLog([]byte(`{"test":"file"}`))
	if err != nil {
		t.Error("could not write log")
	}
}
