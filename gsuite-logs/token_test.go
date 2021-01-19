package gsuitelogs

import (
	"fmt"
	"testing"
)

func TestGetTokenSSM(t *testing.T) {
	token, err := GetTokenSSM()
	if err != nil {
		t.Errorf("%v", err)
	}
	reports, err := token.NewReportClient()
	if err != nil {
		t.Errorf("%v", err)
	}
	fmt.Printf("%v\n", reports)
}
