package main

import (
    "flag"
    "fmt"
    "bufio"
    "os"

    "github.com/ex0dus-0x/pwdcheck/checkup"
    "github.com/ex0dus-0x/pwdcheck/kdf"
)

func main() {
    pwdFromArg := flag.String(
        "p", "password", "Input password as CLI argument (unsafe)"
    )

    reportPath := flag.String(
        "r", "report", "If set, writes a report in JSON to the path given"
    )

    flag.Parse()

    // check if a password was input as a CLI argument
    if pwdFromArg != nil {
        pwd := string(pwdFromArg)

    // otherwise read from a buffered input handler
    } else {
        fmt.Println("Enter your password:")
        reader := bufio.NewReader(os.Stdin)
        pwd, _  := reader.ReadString('\n')
    }


    // initialize a PwdJudge
    judge := PwdJudge

}
