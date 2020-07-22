package main

import (
    "io/ioutil"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"strings"
    "strconv"
    "regexp"

    "github.com/nbutton23/zxcvbn-go"
)

// defines the resultant data parsed from the zxcvbn checkup
type PwdStrength struct {
    score int
    entropy float64
    ttc string
}

// defines the resultant data parsed from a simple sanity check
// given a plaintext password
type SanityCheck struct {
    ShortLen bool
    CommonWords bool
    BasicAlphaNum bool
}

// main interface struct for judging password choices. Given a plaintext
// password, it will go through the checkup flow and store the results for
// user display
type PwdJudge struct {
    Pwd string
    ReportPath *string
    Breach PwnedResp
    Sanity SanityCheck
    Strength PwdStrength
}

// instantiates a new PwdJudge and initializes the default attributes to be set
// later on when parsing out results.
func NewJudge(pwd string) *PwdJudge {
    return &PwdJudge {
        Pwd: pwd,
        ReportPath: nil,
        Breach: PwnedResp {},
        Sanity: SanityCheck {},
        Strength: PwdStrength {},
    }
}

// sets a JSON path to generate a final report for the given pwd hash.
func (j *PwdJudge) SetReportPath(report *string) {
    j.ReportPath = report
}


// runs through the checkup flow, and stores results from different
// steps for later output and consumption.
func (j *PwdJudge) Checkup() (error) {

    // basic sanity check: cleartext pwd is min 8 chars
    shortlen := false
    if len(j.Pwd) < 8 {
        shortlen = true
    }

    // basic sanity check: only contains alphanumeric chars
    alphanum := false
    re := regexp.MustCompile("^[a-zA-Z0-9]*$")
    if re.MatchString(j.Pwd) {
        alphanum = true
    }

    // TODO: basic sanity check: does not contain common words
    commonwords := false

    // perform initial sanity check on password cleartext
    j.Sanity = SanityCheck {
        ShortLen: shortlen,
        CommonWords: commonwords,
        BasicAlphaNum: alphanum,
    }

    // initialize hasher to generate a hash for breach association
    hasher := sha1.New()
    _, err := hasher.Write([]byte(j.Pwd))
    if err != nil {
        return err
    }

    // get a string formatted hash
    pwdhash := strings.ToUpper(hex.EncodeToString(hasher.Sum(nil)))

    // Breach Association: check to see if the original password has associated
    // with a known breach
    client := NewBreachClient()
    resp, err := client.BreachCheck(pwdhash)
    if err != nil {
        return err
    }

    // set breach attribute to response from client
    j.Breach = resp

    // Password Strength: use zxcvbn to quantify strength attributes
    passwordStrength := zxcvbn.PasswordStrength(j.Pwd, nil)

    // initialize PwdStrength struct
    j.Strength = PwdStrength {
        score: passwordStrength.Score,
        entropy: passwordStrength.Entropy,
        ttc: passwordStrength.CrackTimeDisplay,
    }
    return nil
}

// generates an output report for display or file writing
func (j *PwdJudge) MakeOutput() (*[][]string, error) {

    // if filepath is set, write and return
    if j.ReportPath != nil {
        jsonData, _ := json.MarshalIndent(j, "", " ")
        err := ioutil.WriteFile(*j.ReportPath, jsonData, 0644)
        if err != nil {
            return nil, err
        }
        return nil, nil
    }

    // initialize an output table to render
    data := [][]string{
        []string{"Breach Association", strconv.FormatBool(j.Breach.compromised)},
        []string{"Password Strength Score", strings.Repeat("*", j.Strength.score)},
        []string{"Password Entropy", strconv.FormatFloat(j.Strength.entropy, 'E', -1, 64)},
        []string{"Time to Crack", j.Strength.ttc},
    }
    return &data, nil
}
