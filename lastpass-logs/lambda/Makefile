all:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o main main.go
	zip deployment.zip main
	rm -f main

