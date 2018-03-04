package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/mattevans/pwned-passwords"
)

func main() {
	var (
		help  bool
		show  bool
		stdin bool
		one   bool
	)

	flag.BoolVar(&help, "help", false, "Show help and exit.")
	flag.BoolVar(&show, "show", false, "Do not hide the password on input (default false).")
	flag.BoolVar(&one, "one", false, "Check a single password in interactive mode (default false).")
	flag.BoolVar(&stdin, "stdin", false, "Read passwords from STDIN instead of a prompt, one password per line, detects if *any* password is compromised.")

	flag.Parse()

	if help {
		fmt.Println(`Check password against the https://haveibeenpwned.com/Passwords API.
Use -show to echo the password at the prompt.
Use -stdin to check more than one password at once. Does not indicate which password is compromised, only that at least one is compromised.
Exits with the status code 2 if a password was found to be compromised.`)
		os.Exit(0)
	}

	client := hibp.NewClient()

	if stdin {
		scanner := bufio.NewScanner(os.Stdin)

		var pwned bool
		for scanner.Scan() {
			if !pwned {
				// We scan all of STDIN up to EOF, but we don't actually check
				// passwords once we've found one that is compromised.

				p, err := client.Pwned.Compromised(scanner.Text())
				if err != nil {
					fmt.Printf("failed to check password: %v\n", err)
					os.Exit(1)
				}
				if p {
					pwned = true
				}
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("failed to stand STDIN: %v\n", err)
			os.Exit(1)
		}

		if pwned {
			fmt.Println("AT LEAST ONE PASSWORD IS COMPROMISED")
			os.Exit(2)
		} else {
			fmt.Println("no compromised passwords found")
			os.Exit(0)
		}

	} else {
		var pwned bool
		for {
			var (
				line string
				err  error
			)
			if show {
				line, err = readLine("password: ")
			} else {
				line, err = readSecretLine("password: ")
			}
			if err != nil {
				fmt.Printf("failed to read password: %v\n", err)
				os.Exit(1)
			}
			if line == "" {
				break
			}

			p, err := client.Pwned.Compromised(line)
			if err != nil {
				fmt.Printf("failed to check password: %v\n", err)
			}

			if p {
				pwned = true
			}

			if p {
				fmt.Print("THAT PASSWORD IS COMPROMISED\n")
			} else {
				fmt.Print("that password is not compromised\n")
			}
		}

		if pwned {
			os.Exit(2)
		} else {
			os.Exit(0)
		}
	}
}

func readLine(prompt string) (string, error) {
	fmt.Print(prompt)

	s, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		if err == io.EOF {
			return "", nil
		}

		return "", err
	}

	return strings.TrimSuffix(s, "\n"), nil
}

func readSecretLine(prompt string) (string, error) {
	fmt.Print(prompt)

	b, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}

	fmt.Println()

	return strings.TrimSuffix(string(b), "\n"), nil
}
