package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/fffaraz/dns-proxy-go/internal/proxy"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [config-path]\nConfig path defaults to ./config.toml.\n", os.Args[0])
	}
	flag.Parse()
	if flag.NArg() > 1 {
		flag.Usage()
		os.Exit(2)
	}
	configPath := "./config.toml"
	if flag.NArg() == 1 {
		configPath = flag.Arg(0)
	}
	proxy.Run(configPath)
}
