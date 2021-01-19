all:
	rm -f deployment.zip main
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o main slack-logs.go
	zip deployment.zip main
	rm -f main

