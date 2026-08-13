package main

import (
	"context"
	"fmt"
	"os"
	"time"
)

const proofTimeout = 30 * time.Second

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), proofTimeout)
	defer cancel()

	summary, err := executeProof(ctx, os.Getenv("DATABASE_URL"), openPGXPool)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Neon pooled proof failed: %s.\n", err)
		os.Exit(1)
	}
	fmt.Println(summary)
}
