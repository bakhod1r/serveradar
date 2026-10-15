package main

import (
	"os"

	"github.com/bakhod1r/serveradar/internal/interfaces/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:])) }
