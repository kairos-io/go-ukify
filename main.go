package main

import (
	"github.com/itxaka/go-ukify/cmd"
	"log"
	"os"
	"os/signal"
)

func main() {
	// Allow catching SIGINT to exit soon
	go func() {
		sigchan := make(chan os.Signal)
		signal.Notify(sigchan, os.Interrupt)
		<-sigchan
		log.Println("Program killed !")
		os.Exit(1)
	}()

	cmd.Execute()
}
