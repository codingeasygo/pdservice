package main

import (
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/codingeasygo/util/xhttp"
	"github.com/codingeasygo/util/xnet"
)

type LogsArg struct {
	Since      string
	Until      string
	Timestamps bool
	Follow     bool
	Tail       string
	Details    bool
	Help       bool
	ID         string
	Flag       *flag.FlagSet
}

func (l *LogsArg) FlagInit() {
	l.Flag = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	l.Flag.StringVar(&l.Since, "since", "", "Show logs since timestamp (e.g. 2013-01-02T13:23:37Z) or relative (e.g. 42m for 42 minutes)")
	l.Flag.StringVar(&l.Until, "until", "", "Show logs before a timestamp (e.g. 2013-01-02T13:23:37Z) or relative (e.g. 42m for 42 minutes)")
	l.Flag.BoolVar(&l.Timestamps, "timestamps", false, "Show timestamps")
	l.Flag.BoolVar(&l.Timestamps, "t", false, "Show timestamps")
	l.Flag.BoolVar(&l.Follow, "follow", false, "Follow log output")
	l.Flag.BoolVar(&l.Follow, "f", false, "Follow log output")
	l.Flag.StringVar(&l.Tail, "tail", "", `Number of lines to show from the end of the logs (default "all")`)
	l.Flag.StringVar(&l.Tail, "n", "", `Number of lines to show from the end of the logs (default "all")`)
	l.Flag.BoolVar(&l.Details, "details", false, "Show extra details provided to logs")
	l.Flag.BoolVar(&l.Help, "help", false, "Show help")
	l.Flag.BoolVar(&l.Help, "h", false, "Show help")
}

func (l *LogsArg) Encode() string {
	args := url.Values{}
	if len(l.Since) > 0 {
		args.Set("since", l.Since)
	}
	if len(l.Until) > 0 {
		args.Set("until", l.Until)
	}
	if l.Timestamps {
		args.Set("timestamps", "1")
	}
	if l.Follow {
		args.Set("follow", "1")
	}
	if len(l.Tail) > 0 {
		args.Set("tail", l.Tail)
	}
	if l.Details {
		args.Set("details", "1")
	}
	if len(l.ID) > 0 {
		args.Set("id", l.ID)
	}
	return args.Encode()
}

func dockerControl(server string, args ...string) {
	query := ""
	if len(args) > 1 {
		query = "?id=" + args[1]
	}
	res, err := xhttp.GetText("%v/docker/%v%v", server, args[0], query)
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%v\n", res)
	if res != "ok" {
		os.Exit(1)
	}
}

func dockerLogs(server string, args ...string) {
	largs := &LogsArg{}
	largs.FlagInit()
	largs.Flag.Parse(os.Args[1:])
	if largs.Help {
		fmt.Printf("Usage: pdconsole docker logs [OPTIONS]\n")
		fmt.Printf("Options:\n")
		largs.Flag.PrintDefaults()
		return
	}
	if len(largs.Flag.Args()) > 0 {
		largs.ID = largs.Flag.Arg(0)
	}
	wsURL := server + "/docker/logs?" + largs.Encode()
	wsURL = strings.ReplaceAll(wsURL, "http://", "ws://")
	wsURL = strings.ReplaceAll(wsURL, "https://", "wss://")
	wsDialer := xnet.NewWebsocketDialer()
	conn, err := wsDialer.Dial(wsURL)
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
		return
	}
	io.Copy(os.Stdout, conn)
}

func usage() {
	fmt.Printf("Usage: pdconsole COMMAND [OPTIONS]\n")
	fmt.Printf("       pdconsole docker COMMAND [OPTIONS]     to control container\n")
	fmt.Printf("       pdconsole docker start id              to start container\n")
	fmt.Printf("       pdconsole docker stop id               to stop container\n")
	fmt.Printf("       pdconsole docker restart id            to restart container\n")
	fmt.Printf("       pdconsole docker logs [OPTIONS] id     to show container log\n")
}

func main() {
	server := os.Getenv("PDSERVER")
	if len(server) < 1 {
		fmt.Printf("enviroment PDSERVER=http(s)://pdserver-address is required\n")
		os.Exit(1)
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	if os.Args[1] == "-h" || os.Args[1] == "--help" {
		usage()
		os.Exit(0)
	}
	switch os.Args[1] {
	case "docker":
		if len(os.Args) < 3 {
			fmt.Printf("Usage: pdconsole docker COMMAND [OPTIONS]\n")
			os.Exit(1)
		}
		switch os.Args[2] {
		case "start", "stop", "restart", "ps":
			dockerControl(server, os.Args[2:]...)
			return
		case "logs":
			dockerLogs(server, os.Args[2:]...)
			return
		default:
			fmt.Printf("%v is not supported\n", os.Args[2])
			os.Exit(1)
		}
	default:
		fmt.Printf("%v is not supported\n", os.Args[1])
		os.Exit(1)
	}
}
