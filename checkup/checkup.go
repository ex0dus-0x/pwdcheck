package checkup

import (
    "io/ioutil"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
    "os"
	"strings"
    "strconv"

    "github.com/nbutton23/zxcvbn-go"
)

// defines the resultant data parsed from the zxcvbn checkup
type PwdStrength struct {
    score int
    entropy float64
    ttc string
}

// main interface struct for judging password choices. Given a plaintext
// password, it will go through the checkup flow and store the results for
// user display
type PwdJudge struct {
    PwdHash string
    ReportPath *string
    Breach PwnedResp
    Strength PwdStrength
}

// instantiates a new PwdJudge and initializes the default attributes to be set
// later on when parsing out results.
func NewJudge(pwd string) *PwdJudge {
    // initialize hasher
    hasher := sha1.New()
    hasher.Write([]byte(pwd))

    // get a string formatted hash
    pwdhash := strings.ToUpper(hex.EncodeToString(hasher.Sum(nil)))

    return &PwdJudge {
        PwdHash: pwdhash,
        ReportPath: nil,
        Breach: PwnedResp {},
        Strength: PwdStrength {},
    }
}

// sets a JSON path to generate a final report for the given pwd hash.
func (j PwdJudge) SetReportPath(report *string) (error) {
    if _, err := os.Stat(*report); os.IsNotExist(err) {
        return err
    }
    j.ReportPath = report
    return nil
}


// runs through the checkup flow, and stores results from different
// steps for later output and consumption.
func (j PwdJudge) Checkup() (error) {

    // Breach Association: check to see if the original password has associated
    // with a known breach
    client := NewBreachClient()
    resp, err := client.BreachCheck(j.PwdHash)
    if err != nil {
        return err
    }

    // set breach attribute to response from client
    j.Breach = resp

    // Password Strength: use zxcvbn to quantify strength attributes
    passwordStrength := zxcvbn.PasswordStrength(j.PwdHash, nil)

    // initialize PwdStrength struct
    j.Strength = PwdStrength {
        score: passwordStrength.Score,
        entropy: passwordStrength.Entropy,
        ttc: passwordStrength.CrackTimeDisplay,
    }
    return nil
}

// generates an output report for display or file writing
func (j PwdJudge) MakeOutput() (*[][]string, error) {

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
        []string{"Password Strength Score", strconv.Itoa(j.Strength.score)},
        []string{"Password Entropy", strconv.FormatFloat(j.Strength.entropy, 'E', -1, 64)},
        []string{"Time to Crack", j.Strength.ttc},
    }
    return &data, nil
}
