package checkup

import (
    "net/http"
    "io/ioutil"
    "time"
    "strings"
    "strconv"
    "fmt"
)

const (
    // url endpoint used for API requests
    BaseURL string = "https://api.pwnedpasswords.com/range/"

    // timeout to wait for before canceling request
    DefaultClientTimeout time.Duration = 30 * time.Second
)


// defines API client type for the PwnedPasswords service
type PwnedClient struct {
    client http.Client
    baseURL string
}

type PwnedResp struct {
    prefix string
    compromised bool
    occurrences int
}

// instantiates a new client for interaction
func NewBreachClient() *PwnedClient {
    return &PwnedClient {
        client: http.Client {
            Timeout: DefaultClientTimeout,
        },
        baseURL: BaseURL,
    }
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
func (cl *PwnedClient) BreachCheck(pwdhash string) (PwnedResp, error) {

    // get 5-byte prefix and suffix from our hash
    prefix := strings.ToUpper(pwdhash[:5])
    suffix := strings.ToUpper(pwdhash[5:])

    // initialize result to return
    var pwnedResp PwnedResp

    // send GET request to API service and error-handle
    resp, err := cl.client.Get(cl.BuildURL(prefix))
    if err != nil {
        return pwnedResp, err
    }
    defer resp.Body.Close()

    // read body from response
    bodyBytes, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return pwnedResp, err
    }

    bodyString := string(bodyBytes)
    hashStrings := []string(strings.Split(bodyString, "\n"))

    // range each line of the response
    for _, res := range hashStrings {

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

    pwnedResp.prefix = prefix
    return pwnedResp, nil
}
