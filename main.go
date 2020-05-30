package main

import (
    "flag"
    "fmt"
    "strings"
    "syscall"
    "os"

    "golang.org/x/crypto/ssh/terminal"
    "github.com/olekukonko/tablewriter"
    "github.com/ex0dus-0x/pwdcheck/checkup"
    //"github.com/ex0dus-0x/pwdcheck/kdf"
)

func readPassword() (string, error) {

    // read password without displaying chars
    pwd, err := terminal.ReadPassword(int(syscall.Stdin))
    if err != nil {
        return "", err
    }

    // parse out as string and return
    password := string(pwd)
    return strings.TrimSpace(password), nil
}

func main() {
    pwdFromArg := flag.String(
        "password", "", "Input password as CLI argument (unsafe)",
    )

    reportPath := flag.String(
        "report", "", "If set, writes a report in JSON to the path given",
    )

    flag.Parse()

    // stores the parsed password, either as a param or from STDIN
    var pwd string

    // check if a password was input as a CLI argument
    if *pwdFromArg != "" {
        pwd = string(*pwdFromArg)

    // otherwise read from a buffered input handler
    } else {
        fmt.Print("[>] Enter your password: ")

        // read buffered input string and error check
        var err error
        pwd, err = readPassword()
        if err != nil {
            fmt.Errorf("cannot read input password: ", err)
        }
        fmt.Print("\n")
    }

    // initialize a PwdJudge to pass upon judgement
    judge := checkup.NewJudge(pwd)
    if *reportPath != "" {
        judge.SetReportPath(reportPath)
    }

    fmt.Println("[*] Judging your password...")

    // run the checkup flow
    judge.Checkup()

    // get output results
    outData, err := judge.MakeOutput()
    if err != nil {
        fmt.Errorf("cannot generate output: ", err)
    }

    // if table is generated, output it
    if outData != nil {
        table := tablewriter.NewWriter(os.Stdout)
        table.SetHeader([]string{"Checkup", "Status"})

        for _, v := range *outData {
            table.Append(v)
        }
        table.Render()
    }
}
