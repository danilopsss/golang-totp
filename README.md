# Time-Based One-Time Password (TOTP) Generator

This is a simple implementation of a TOTP generator in Go. TOTP is an algorithm that computes a one-time passcode from a shared secret key and the current time.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

- Go (version 1.16 or later)

### Installing

1. Clone the repository to your local machine using `git clone`.
2. Navigate to the project directory.
3. Run the program with the command `go run main.go`.

## Usage

The program generates a TOTP using the HMAC-SHA1 algorithm. Here's a brief explanation of the functions:

- `GenerateCounter(epochTime int) []byte`: This function generates an 8-byte counter based on the current epoch time divided by 30.
- `GenerateHmac(t *TOTP, epochTime int) []byte`: This function generates an HMAC value using the shared secret key and the counter.
- `DynamicTruncation(hmac []byte, epochTime int) int`: This function performs dynamic truncation on the HMAC value to generate a 4-byte string.
- `(t *TOTP) GenerateOTP(epochTime int) string`: This function generates the final OTP by taking the modulo of the truncated HMAC value with 10^6.

The `main` function gets the current epoch time, defines a shared secret key, and prints the generated OTP.

Please note that the shared secret key is hardcoded in this example. In a real-world application, you would typically get this key from a secure source or user input.