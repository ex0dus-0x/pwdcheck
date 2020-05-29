package checkup

import (
    "crypto/sha1"
    "net/http"
    "time"
    "strings"
    "strconv"
    "fmt"
    "encoding/hex"
)

const (
    // url endpoint used for API requests
    BaseURL string = "https://api.pwnedpasswords.com/range/"

    // timeout to wait for before canceling request
    DefaultClientTimeout time.Duration = 30 * time.Second
)


// defines API client type for the PwnedPasswords service
type PwnedClient struct {
    client *http.Client
    baseURL string
}

type PwnedResp struct {
    hash string
    compromised bool
    occurrences int
}

// instantiates a new client for interaction
func NewClient() *PwnedClient {
    return &PwnedClient {
        client: &http.Client {
            Timeout: DefaultClientTimeout,
        },
        baseURL: BaseURL,
    }
}

// override the timeout set for debugging purposes
func (cl *PwnedClient) SetTimeout(d time.Duration) {
    cl.client.Timeout = d
}

// helper to initialize URL for request
// TODO: add more configurations
func (cl *PwnedClient) BuildURL(prefix string) string {
    finalURL := fmt.Sprintf("%s/%s", cl.baseURL, prefix)
    return finalURL
}

// gets all hash entries from the k-anonymized PwnedPassword dataset by
// submitting a query of the password SHA hash's prefix, and checks if the
// original hash is in the resultant queryset.
func (cl *PwnedClient) BreachCheck(pwd string) (PwnedResp, error) {

    // initialize hasher
    hasher := sha1.New()
    hasher.Write([]byte(pwd))

    // get a string formatted hash
    h := strings.ToUpper(hex.EncodeToString(hasher.Sum(nil)))

    // get 5-byte prefix and suffix from our hash
    prefix := strings.ToUpper(h[:5])
    suffix := strings.ToUpper(h[5:])

    // create builder
    req, err := cl.client.NewRequest("GET", cl.BuildURL(prefix), nil)
    if err != nil {
        return PwnedResp {}, err
    }

    // send GET request to API service and error-handle
    resp, err := cl.client.Do(req)
    if err != nil {
        return PwnedResp {}, err
    }

    // initialize result to return
    var pwnedResp PwnedResp
    pwnedResp.hash = string(h)

    // range each line of the response
    for _, res := range resp {

        // if present, get the number of occurrences too
        if string(res[:35]) == suffix {
            _ , err = strconv.ParseInt(res[36:], 10, 64)
            if err != nil {
                return PwnedResp {}, err
            }

            pwnedResp.compromised = true
            pwnedResp.occurrences += 1
        }
    }

    return pwnedResp, nil
}
