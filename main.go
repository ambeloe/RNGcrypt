package main

import (
	"flag"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
	"io"
	"os"
	"syscall"
)

func main() {
	os.Exit(rMain())
}

func rMain() int {
	var err error

	var decompress = flag.Bool("d", false, "decrypt")

	var inFile = flag.String("i", "", "input filename (reads from stdin if not set)")
	var outFile = flag.String("o", "", "output filename (writes to stdout if not set)")

	var keyIn = flag.String("k", "", "key(NO KDF APPLIED) to use (does not prompt)")

	flag.Parse()

	var inF []byte
	var outF []byte

	var key []byte

	if *inFile == "" {
		inF, err = io.ReadAll(os.Stdin)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "error reading file from stdin:", err)
			return 1
		}
	} else {
		inF, err = os.ReadFile(*inFile)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "error reading file from disk:", err)
			return 1
		}
	}

	if *keyIn == "" {
		//user supplied password so apply key engoodening
		var password []byte
		fmt.Print("password: ")
		password, err = term.ReadPassword(syscall.Stdin)
		//add a salt for shits and giggles
		key = argon2.IDKey(password, nil, 1, 64*1024, 4, keyLen)
	}

	if !*decompress {
		outF, err = RNGcryptEncrypt(key, inF)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "error encrypting", err)
			return 1
		}
	} else {
		outF, err = RNGcryptDecrypt(key, inF)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "error decrypting", err)
			return 1
		}
	}

	if *outFile == "" {
		_, err = os.Stdout.Write(outF)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "error writing file to stderr", err)
			return 1
		}
	} else {
		err = os.WriteFile(*outFile, outF, 0644)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "error writing file", err)
			return 1
		}
	}

	return 0
}
