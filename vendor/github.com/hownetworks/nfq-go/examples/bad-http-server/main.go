package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"

	nfq "github.com/hownetworks/nfq-go"
)

func main() {
	queue, err := nfq.New(0, func(pkt nfq.Packet) {
		if rand.Float64() < 0.10 {
			pkt.Drop()
		} else {
			pkt.Accept()
		}
	})
	if err != nil {
		log.Panic(err)
	}
	defer queue.Close()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, World!")
	})
	fmt.Println("Listening on port 8080 and dropping 10% of packets")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
