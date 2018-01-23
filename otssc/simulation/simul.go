package main

import (
	_ "github.com/dedis/onchain-secrets/service"
	"gopkg.in/dedis/onet.v1/simul"
)

func main() {
	simul.Start()
}
