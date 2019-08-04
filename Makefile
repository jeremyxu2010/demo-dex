build-dex:
	go get github.com/dexidp/dex
	go build -o bin/dexserver github.com/dexidp/dex/cmd/dex

build-dexclient:
	go build -o bin/dexclient github.com/jeremyxu2010/demo-dex/cmd/dexclient

run-dexserver:
	bin/dexserver serve config/dexserver-config.yaml

run-dexclient:
	bin/dexclient