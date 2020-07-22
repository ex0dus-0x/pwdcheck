# pwdcheck

Small utility that criticizes your password choices (for the sake of security!)

## Introduction

`pwdcheck` is an opinionated password checkup utility and generator that consumes a potential password you want to use, actively judges it against some criteria, and generates statistics from that criteria set, and outputs them for your consumption.

### Use Cases

__NOTE__: this is not super serious software! Just represents some experimenting around when learning more about modern password breach mitigations.

* Password strength checking for mission-critical webapps
* Data analysis on breached credential datasets

## Checkup Flow

The _checkup flow_ contains the following steps:

1. __Breach Association__

Checks against PwnedPassword's k-anonymized dataset in order to determine if the credential is potentially as part of
a large combination list. Passwords that are associated should be rejected as choices for key generation (see __Questions__).

2. __Sanity Check__

Applies rudimentary checks against a cleartext string, in order to determine if there are already any questionable patterns existing.

2. __Password Strength__

Uses the zxcvbn to quantify password strength, which provides an insight given its own strength algorithm.

## Usage

To download and install:

```
$ go get -u github.com/ex0dus-0x/pwdcheck
$ pwdcheck -h
  -password string
        Input password as CLI argument (unsafe)
  -report string
        If set, writes a report in JSON to the path given
```

## Questions

### 1. Why check for presence in a breach if a better password is being generated anyways?

If such theft-resistant password derivation schemes become more prevalent, attackers might start
incorporating KDF schemes as part of the credential reuse campaign to derive potential permutations
of passwords for different services.

### 2. What should I do if `pwdcheck` judges my password poorly?

You should consider a service that may incorporate a deterministic password generator in order to generate unique and more cryptographically secure passwords and keys for use instead of what you have, especially if you are a big password re-user.

## License

[MIT License](https://codemuch.tech/license.txt)
