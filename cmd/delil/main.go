// Command delil is the DƏLİL command-line tool.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/serxan22/delil/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
