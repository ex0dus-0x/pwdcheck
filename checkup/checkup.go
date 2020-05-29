package checkup

import (
    "github.com/ex0dus-0x/pwdcheck/checkup/breach"
)

type PwdStrength struct {
    score int
    entropy int
    ttc string
}

type PwdJudge struct {
    pwd string
    breach PwnedRes
    strength PwdStrength
}

func NewJudge(pwd string) *PwdJudge {
    return &PwdJudge {
        pwd: pwd
        breach: nil
        strength: PwdStrength {}
    }
}

func (j PwdJudge) Checkup() {

    // calculate strength using zxcvbn
    passwordStrength := zxcvbn.PassswordStrength(j.pwd, nil)

    // initialize PwdStrength struct
    j.strength = PwdStrength {
        score: passwordStrength.Score,
        entropy: passwordStrength.Entropy,
        ttc: passwordStrength.CrackTimeDisplay
    }
}
