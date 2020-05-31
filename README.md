# pwdcheck

small utility that criticizes your password choices (for the sake of security!)

## Introduction

`pwdcheck` is an opinionated password checkup utility and generator that consumes a potential
password you want to use, actively judges it against some criteria, and uses a Pwdhhash-inspired deterministic password generation scheme to create a unique and secure password you can use (TODO: automate the input process into forms, like PwdHash does).

## Design

### Checkup Flow

The _checkup flow_ contains the following steps:

1. __Breach Association__

Checks against PwnedPassword's k-anonymized dataset in order to determine if the credential is potentially as part of
a large combination list. Passwords that are associated should be rejected as choices for key generation (see __Questions__).

2. __Password Strength__

Uses the zxcvbn to quantify password strength.

(TODO)

### Password Derivation Scheme

`pwdcheck` also has the capability to determinstically generate passwords given an original secret password and the domain name being authenticated against. This is largely inspired by Stanford's [PwdHash](https://pwdhash.github.io/website/), which is a browser plugin that can create theft-resistant passwords while remaining memory-less.

A browser plugin that calls back to the original Go implementation will be released in order to better model functionality like Pwdhash and any other deterministic password generation schemes, while the CLI will be mostly used as a Proof-Of-Concept or reference implementation.

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

## License

[MIT License](https://codemuch.tech/license.txt)
