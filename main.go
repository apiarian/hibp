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

	var (
		pwned bool
		err   error
	)
	if stdin {
		pwned, err = checkStdin(client)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		pwned, err = checkLines(client, show, one)
		if err != nil {
			fmt.Println(err)
		}
	}

	if pwned {
		os.Exit(2)
	} else {
		if err != nil {
			os.Exit(1)
		}

		os.Exit(0)
	}
}

func checkStdin(client *hibp.Client) (bool, error) {
	scanner := bufio.NewScanner(os.Stdin)

	var pwned bool
	for scanner.Scan() {
		if !pwned {
			// We scan all of STDIN up to EOF, but we don't actually check
			// passwords once we've found one that is compromised.

			p, err := client.Pwned.Compromised(scanner.Text())
			if err != nil {
				return pwned, fmt.Errorf("failed to check password: %v", err)
			}
			if p {
				pwned = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return pwned, fmt.Errorf("failed to scan STDIN: %v", err)
	}

	if pwned {
		fmt.Println("AT LEAST ONE PASSWORD IS COMPROMISED")
	} else {
		fmt.Println("none of the passwords are compromised")
	}

	return pwned, nil
}

func checkLines(client *hibp.Client, show, one bool) (bool, error) {
	var pwned bool
	for {
		var (
			line string
			err  error
		)
		if show {
			line, err = readLine("password (blank to exit): ")
		} else {
			line, err = readSecretLine("password (blank to exit): ")
		}
		if err != nil {
			return pwned, fmt.Errorf("failed to read password: %v", err)
		}
		if line == "" {
			break
		}

		p, err := client.Pwned.Compromised(line)
		if err != nil {
			return pwned, fmt.Errorf("failed to check password: %v", err)
		}

		if p {
			pwned = true
		}

		if p {
			fmt.Println("THAT PASSWORD IS COMPROMISED")
		} else {
			fmt.Println("that password is not compromised")
		}

		if one {
			break
		}
	}

	return pwned, nil
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
