LDFLAGS = -s -w

all:
	mkdir -p deploy && rm -f deploy/*
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o deploy/main main.go
	cd deploy && zip deployment.zip main

