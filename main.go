package main

/*

This is meant to run behind a web server like nginx which handles TLS/capping POST size/rate-limiting/etc.

*/

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/awnumar/memguard"
	badger "github.com/dgraph-io/badger/v3"
	"github.com/vmihailenco/msgpack/v5"
	gomail "gopkg.in/gomail.v2"
)

const (
	keyPrefixCT = "ct_" // ctRecord
	keyPrefixIP = "ip_" // ipRecord
	keyPrefixRV = "rv_" // rvRecord
)

var (
	config     globalConfig
	db         *badger.DB
	ctIDRX     *regexp.Regexp
	emailRX    *regexp.Regexp
	randFac    chan [8]byte
	hmacSecret *memguard.LockedBuffer
	hIPSecrets []*memguard.LockedBuffer
	gidCounter = randUInt32()
	getKeys    activeGetKeys
)

// values in config file
type globalConfig struct {
	DBPath        string
	Debug         bool
	Listen        string
	HCSiteKey     string
	HCSecret      string
	AbuseMail     string
	Mail          string
	RealIPHeader  string
	RTLRRMinRatio float64
	RTLRR         map[int]map[int]int64 // RTL Range Ratio
	RTLRRMinRange int
}

// json response to all api calls
type response struct {
	Error  string
	Result interface{}
}

// limits sGetHandler transactions for the same key to one at a time
type activeGetKeysWaiter struct {
	wait  chan struct{}
	count int
}

type activeGetKeys struct {
	sync.Mutex
	active map[string]*activeGetKeysWaiter
}

// limits the number of times /contact api endpoint can be used
var contactLimiter struct {
	sync.Mutex
	i int
}

// stats we store on securely hashed IP address using /api
// this information is only used to track down and stop abuse of /api
// all ipRecords are automatically deleted... just like everything else
type ipRecord struct {
	Gets       int   // total sGet
	Sets       int   // total sSet
	Retrievals int   // total messages sent by this network that were retrieved
	RTLs       int   // total RTL associated with Sets
	TTLs       int   // total TTL associated with Sets
	Complaints int   // total abuse/spam complaints specifying messages sent from this ip
	Created    int64 // created timestamp
	Updated    int64 // last updated timestamp
}

// encrypted message record
type ctRecord struct {
	CT      string // ciphertext
	RTL     int    // retrievals-to-live
	TTL     int    // time-to-live
	HIP     string // hashed IP
	Captcha bool   // is a captcha required?
	NoCopy  bool   // easy to copy decrypted result?
	Created int64  // created timestamp
	Updated int64  // last updated timestamp
}

// temporary retrieval record keyed off of ctRecord used to handle spam complaints
// since by the time a user can complain about spam, the ctRecord may already be deleted
// stores the HIP/Created from the ctRecord briefly
type rvRecord struct {
	HIP     string // hashed IP
	Created int64  // created timestamp
}

func init() {

	// Make less calls to rand.Read by reading in 256 bytes each time
	randFac = make(chan [8]byte, 1000)
	var b [256]byte
	var count int64
	go func(randFac chan [8]byte) {
		for {
			cur := count & 0xF
			count++
			if cur == 0 {
				_, err := rand.Read(b[:])
				if err != nil {
					log.Panicln(err)
				}
			}
			start, end := cur*8, (cur+1)*8
			var out [8]byte
			copy(out[:], b[start:end])
			randFac <- out
		}
	}(randFac)

	// HMAC secret updates on restart
	hmacSecret = memguard.NewBufferRandom(32)

	// init getKeys for use in sGetHandler
	getKeys.active = make(map[string]*activeGetKeysWaiter)

	// ludicrous amount of bits to hash IPs protected by guard pages
	// why more than one? if someone could read process memory, they can get the secrets used to hash IPs
	// if they attempt to read a secret and trip a guard page, the process crashes and the remaining
	// secrets are hopefully lost - thereby rendering any stored hashed IPs useless
	// how much extra protection does this really provide if someone has already gained
	// enough access to read process memory?  not sure, but at least its something
	for i := 0; i < 10; i++ {
		hIPSecrets = append(hIPSecrets, memguard.NewBufferRandom(32))
	}

	// Validation regexes
	ctIDRX = regexp.MustCompile(`^[a-zA-Z0-9_\-]{10,20}$`)
	emailRX = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

}

// Generate a secure url-friendly global-enough ID
// We delete everything shortly after it is stored so
// randomness is more important that perfect uniqueness
func getGID() string {
	var gid [11]byte
	i := atomic.AddUint32(&gidCounter, 1)
	gid[0] = byte(i >> 16)
	gid[1] = byte(i >> 8)
	gid[2] = byte(i)
	randBytes := <-randFac
	gid[3] = randBytes[0]
	gid[4] = randBytes[1]
	gid[5] = randBytes[2]
	gid[6] = randBytes[3]
	gid[7] = randBytes[4]
	gid[8] = randBytes[5]
	gid[9] = randBytes[6]
	gid[10] = randBytes[7]
	return base64.RawURLEncoding.EncodeToString(gid[:])
}

// A random uint32
func randUInt32() uint32 {
	b := make([]byte, 3)
	if _, err := rand.Reader.Read(b); err != nil {
		log.Panicln(err)
	}
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

// Create a secure hash of an IP (IPv4 or 6 - all the same to us since it is a string)
// this only yields consistent hashing for the same IP between process restarts
// this is of course annoying but a necessary tradeoff to ensure IP privacy
func hashIP(ip string, secret []byte) string {
	for _, hip := range hIPSecrets {
		secret = append(secret, hip.Bytes()...)
	}
	hmac := hmac.New(sha256.New, secret)
	_, err := hmac.Write([]byte(ip))
	if err != nil {
		log.Panicln(err)
	}
	return fmt.Sprintf("%x", hmac.Sum(nil))
}

// encode a record for DB storage
func encodeRecord(record interface{}) []byte {
	b, err := msgpack.Marshal(record)
	if err != nil {
		log.Panicln(err)
	}
	return b
}

// decodes an ipRecord
func decodeIPRecord(eipr []byte) *ipRecord {
	ipr := &ipRecord{}
	err := msgpack.Unmarshal(eipr, ipr)
	if err != nil {
		log.Panicln(err)
	}
	return ipr
}

// decodes an ctRecord
func decodeCTRecord(ectr []byte) *ctRecord {
	ctr := &ctRecord{}
	err := msgpack.Unmarshal(ectr, ctr)
	if err != nil {
		log.Panicln(err)
	}
	return ctr
}

// decodes an rvRecord
func decodeRVRecord(ectr []byte) *rvRecord {
	ctr := &rvRecord{}
	err := msgpack.Unmarshal(ectr, ctr)
	if err != nil {
		log.Panicln(err)
	}
	return ctr
}

// Update stats for hashed anonymous IP - also returns the current record (if any)
// IPs are hashed using hashIP() in a way that prevents deriving the IP from the hash
// stats on IPs are only kept to help prevent abuse/spam - most records last for only 5 minutes
func ipStats(txn *badger.Txn, hashedIP string, update map[string]int) (*ipRecord, error) {

	// get existing ipRecord if any
	var ipr *ipRecord
	item, err := txn.Get([]byte(keyPrefixIP + hashedIP))
	if err == badger.ErrKeyNotFound || item.IsDeletedOrExpired() {
		ipr = &ipRecord{}
	} else if err != nil {
		return nil, err
	} else {
		item.Value(func(val []byte) error {
			ipr = decodeIPRecord(val)
			return nil
		})
	}

	// if there is nothing to update, just return the record
	if update == nil {
		return ipr, nil
	}
	now := time.Now()

	// update components of ipRecord
	for k, v := range update {
		switch k {
		case "Gets":
			ipr.Gets += v
		case "Sets":
			ipr.Sets += v
		case "Retrievals":
			ipr.Retrievals += v
		case "RTLs":
			ipr.RTLs += v
		case "TTLs":
			ipr.TTLs += v
		case "Complaints":
			ipr.Complaints += v
		}
	}

	// we cannot store information on all securely hashed IP addresses - we cannot afford those computing resources
	// we just want to store information about possible abusers/spammers and quickly delete all other info
	// the goal of the below TTL settings is to accomplish this...

	// default TTL
	ttl := time.Second * time.Duration(300) // 5 minutes for the vast majority of users
	if ipr.Created == 0 {
		ipr.Created = now.Unix()
	} else {

		// retrievals / totalrtl ratio provides a good indicator for spaminess once totalrtl is high enough
		den := 1
		if ipr.RTLs > 0 { // this can be zero in a couple scenarios
			den = ipr.RTLs
		}
		retrievalsToRTLs := float64(ipr.Retrievals) / float64(den)

		// conditions which can lengthen the default TTL
		if ipr.Complaints > 0 {
			// we have received spam complaints
			ttl = time.Second * time.Duration(2419200) // 4 weeks
		} else if ipr.RTLs >= 2500 && retrievalsToRTLs < .2 {
			ttl = time.Second * time.Duration(1209600) // 2 weeks
		} else if ipr.RTLs >= 1000 && retrievalsToRTLs < .2 {
			ttl = time.Second * time.Duration(604800) // 1 week
		} else if ipr.RTLs >= 500 && retrievalsToRTLs < .2 {
			ttl = time.Second * time.Duration(86400) // 1 day
		} else if ipr.RTLs >= 500 {
			ttl = time.Second * time.Duration(3600) // 1 hour
		} else if ipr.RTLs >= 250 {
			ttl = time.Second * time.Duration(1800) // 30 minutes
		} else if ipr.RTLs >= 50 {
			ttl = time.Second * time.Duration(600) // 10 minutes
		}
	}

	ipr.Updated = now.Unix()
	if config.Debug {
		log.Println("iprecord: " + fmt.Sprintf("%+v", ipr))
	}
	entry := badger.NewEntry([]byte(keyPrefixIP+hashedIP), encodeRecord(ipr)).WithTTL(ttl)
	err = txn.SetEntry(entry)
	if err != nil {
		return nil, err
	}
	return ipr, nil
}

// retrieves a CT record and increments/decrements associated stats
func sGetHandler(rw http.ResponseWriter, req *http.Request) {
	response := &response{}
	if req.Method != "POST" {
		response.Error = "Only POST accepted"
		printResponse(response, rw, http.StatusInternalServerError)
		return
	}
	body, err := ioutil.ReadAll(req.Body) // upstream caps body size for us
	if err != nil {
		response.Error = "Communication error"
		printResponse(response, rw, http.StatusInternalServerError)
		return
	}
	if config.Debug {
		log.Println("sGetHandler req: " + string(body))
	}
	var request struct {
		ID    string
		Token string
	}
	type getResult struct {
		CT      string
		Captcha bool // set to true to tell the client they need to pass a captcha first
		NoCopy  bool
	}
	err = json.Unmarshal(body, &request)
	if err != nil {
		response.Error = "Malformed json/post sent in request"
		printResponse(response, rw, http.StatusOK)
		return
	} else if !ctIDRX.MatchString(request.ID) {
		response.Error = "Invalid ID"
		printResponse(response, rw, http.StatusOK)
		return
	}
	if request.Token != "" {
		cPass, err := hCaptchaVerify(request.Token)
		if err != nil {
			log.Println(err)
			response.Error = "Problem verifying captcha"
			printResponse(response, rw, http.StatusOK)
			return
		}
		if !cPass {
			// they must try again
			log.Println("Captcha verification failed")
			response.Result = getResult{
				Captcha: true,
			}
			printResponse(response, rw, http.StatusOK)
			return
		}
	}
	var ctr *ctRecord
	cRequired := errors.New("captcha required")
	now := time.Now()

	// Users need assurance that if a message was set to only ever be retrieved once, that it can indeed
	// only be retrieved once. It is possible given badgerdb, although unlikely, that a timing attack could
	// be used to retrieve a message more than once if a bunch of gets came in before the transaction was
	// committed.  We therefore guard against this to ensure that there can only ever be one open transaction
	// for the same key.

	var waiter *activeGetKeysWaiter
	getKey := keyPrefixCT + request.ID
	exists := true
	for exists {
		getKeys.Lock()
		waiter, exists = getKeys.active[getKey]
		if exists {
			waiter.count++
			count := waiter.count
			getKeys.Unlock()
			if count > 3 {
				// discourage this sort of thing - should be extremely rare to non-existent outside of it being done on purpose
				log.Println("Requests fighting for same key")
				response.Error = "Invalid ID"
				printResponse(response, rw, http.StatusInternalServerError)
				return
			}
			time.Sleep(1 * time.Second)
			<-waiter.wait
		} else {
			waiter = &activeGetKeysWaiter{wait: make(chan struct{})}
			getKeys.active[getKey] = waiter
			getKeys.Unlock()
		}
	}
	defer func() {
		go func() {
			getKeys.Lock()
			delete(getKeys.active, getKey)
			close(waiter.wait)
			getKeys.Unlock()
		}()
	}()

	// NOTE: we issue an update transaction here since excluding the scenario where the key
	// does not exist, we have to update/delete the record for RTL anwyays

	err = db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(getKey))
		if err != nil {
			return err // record either does not exist or we have problems
		}
		if item.IsDeletedOrExpired() {
			// is this even needed?
			return badger.ErrKeyNotFound
		}
		err = item.Value(func(val []byte) error {
			ctr = decodeCTRecord(val)
			return nil
		})
		if err != nil {
			return err
		}
		hashedIP := hashIP(req.Header.Get(config.RealIPHeader), stoHIPSecret(req))
		_, err = ipStats(txn, hashedIP, map[string]int{"Gets": 1})
		if err != nil {
			return err
		}
		_, err = ipStats(txn, ctr.HIP, map[string]int{"Retrievals": 1})
		if err != nil {
			return err
		}
		if ctr.Captcha && request.Token == "" {
			err = cRequired
		} else if ctr.RTL <= 1 {
			// we have to delete this record since this is the last allowed read
			// but before we do create a rvRecord in case the user reports this message as spam
			rvr := &rvRecord{
				HIP:     ctr.HIP,
				Created: ctr.Created,
			}
			// we give them 10 minutes to decide if it is spam
			entry := badger.NewEntry([]byte(getKey), encodeRecord(rvr)).WithTTL(time.Second * time.Duration(600))
			err = txn.SetEntry(entry)
			if err != nil {
				return err
			}
			// delete CT record
			err = txn.Delete([]byte(getKey))
		} else {
			// we have to decrement rtl
			ctr.RTL--
			ctr.Updated = now.Unix()
			ctrRecord := encodeRecord(ctr)
			entry := badger.NewEntry([]byte(getKey), ctrRecord).WithTTL(time.Second * time.Duration(int64(item.ExpiresAt())-now.Unix()))
			err = txn.SetEntry(entry)
		}
		return err
	})
	if err != nil {
		if err == badger.ErrKeyNotFound {
			response.Error = "Record not found"
			printResponse(response, rw, http.StatusOK)
		} else if err == cRequired {
			// we cannot serve the CT until they pass a captcha
			response.Result = getResult{
				Captcha: true,
			}
			printResponse(response, rw, http.StatusOK)
			return
		} else {
			// we need to know about this type of error
			log.Println(err) // should we bail here instead?
			response.Error = "Database error"
			printResponse(response, rw, http.StatusInternalServerError)
		}
		return
	}
	response.Result = getResult{
		CT:     ctr.CT,
		NoCopy: ctr.NoCopy,
	}
	printResponse(response, rw, http.StatusOK)
}

// creates a new CT record - this stores a new encrypted temporary message
func sSetHandler(rw http.ResponseWriter, req *http.Request) {
	response := &response{}
	if req.Method != "POST" {
		response.Error = "Only POST accepted"
		printResponse(response, rw, http.StatusInternalServerError)
		return
	}
	body, err := ioutil.ReadAll(req.Body) // upstream caps body size for us
	if err != nil {
		response.Error = "Communication error"
		printResponse(response, rw, http.StatusInternalServerError)
		return
	}
	if config.Debug {
		log.Println("sSetHandler req: " + string(body))
	}
	var request struct {
		CT       string // ciphertext to set - only used for set
		TTL      int    // time-to-live - only used for set
		RTL      int    // reads-to-live - only used for set
		HMAC     string // HMAC verifiy iterations
		Deadline int64  // unix time deadline
		Captcha  bool   // require captcha for recipient
		NoCopy   bool   // make copying the plaintext more difficult
	}
	err = json.Unmarshal(body, &request)

	// do we have valid input?

	now := time.Now()
	if err != nil {
		if config.Debug {
			log.Println(err)
		}
		response.Error = "Malformed/invalid json"
		printResponse(response, rw, http.StatusOK)
		return
	} else if request.CT == "" {
		response.Error = "CT not specified"
		printResponse(response, rw, http.StatusOK)
		return
	} else if request.HMAC == "" {
		response.Error = "HMAC not specified"
		printResponse(response, rw, http.StatusOK)
		return
	} else if request.Deadline == 0 {
		response.Error = "Deadline not specified"
		printResponse(response, rw, http.StatusOK)
		return
	} else if request.TTL < 60 || request.TTL > 1209600 {
		response.Error = "TTL must be between 60 and 1209600"
		printResponse(response, rw, http.StatusOK)
		return
	} else if request.RTL < 1 || request.RTL > 30 {
		response.Error = "RTL must be between 1 and 30"
		printResponse(response, rw, http.StatusOK)
		return
	} else if request.Deadline < now.Unix() {
		response.Error = "Deadline has passed"
		printResponse(response, rw, http.StatusOK)
		return
	}
	ctParts := strings.Split(request.CT, "~")
	if len(ctParts) != 4 {
		response.Error = "Invalid CT"
		printResponse(response, rw, http.StatusOK)
		return
	}
	hmac := hmac.New(sha256.New, hmacSecret.Bytes())
	_, err = hmac.Write([]byte(ctParts[0] + strconv.Itoa(int(request.Deadline))))
	if err != nil {
		log.Panicln(err)
	}
	compareNew := []byte(base64.RawURLEncoding.EncodeToString(hmac.Sum(nil)))
	compareReq := []byte(request.HMAC)
	if subtle.ConstantTimeCompare(compareNew, compareReq) == 0 {
		response.Error = "Invalid HMAC/Iter/Deadline"
		printResponse(response, rw, http.StatusOK)
		return
	}
	gid := getGID()
	err = db.Update(func(txn *badger.Txn) error {
		hashedIP := hashIP(req.Header.Get(config.RealIPHeader), stoHIPSecret(req))
		_, err := ipStats(txn, hashedIP, map[string]int{
			"Sets": 1,
			"RTLs": request.RTL,
			"TTLs": request.TTL,
		})
		if err != nil {
			return err
		}
		ctRecord := &ctRecord{
			CT:      request.CT,
			RTL:     request.RTL,
			TTL:     request.TTL,
			HIP:     hashedIP,
			Captcha: request.Captcha,
			NoCopy:  request.NoCopy,
			Created: now.Unix(),
			Updated: now.Unix(),
		}
		entry := badger.NewEntry([]byte(keyPrefixCT+gid), encodeRecord(ctRecord)).WithTTL(time.Second * time.Duration(request.TTL))
		err = txn.SetEntry(entry)
		return err
	})
	if err != nil {
		log.Println(err) // should we bail here instead?
		response.Error = "Database error"
		printResponse(response, rw, http.StatusInternalServerError)
		return
	}
	response.Result = struct {
		ID   string
		BURL string
	}{
		gid,
		"https://deletebin.org/s",
	}
	//response.Error = ""
	printResponse(response, rw, http.StatusOK)

}

// handles form submission requests where the user expects to reach a person
func contactHandler(rw http.ResponseWriter, req *http.Request) {
	response := &response{}
	if req.Method != "POST" {
		response.Error = "Only POST accepted"
		printResponse(response, rw, http.StatusInternalServerError)
		return
	}
	body, err := ioutil.ReadAll(req.Body) // upstream caps body size for us
	if err != nil {
		response.Error = "Communication error"
		printResponse(response, rw, http.StatusInternalServerError)
		return
	}
	if config.Debug {
		log.Println("contactHandler req: " + string(body))
	}
	var request struct {
		Name    string
		Email   string
		Message string
		Route   string
	}
	err = json.Unmarshal(body, &request)

	// do we have valid input?
	if err != nil {
		if config.Debug {
			log.Println(err)
		}
		response.Error = "Malformed/invalid json"
		printResponse(response, rw, http.StatusOK)
		return
	} else if request.Message == "" {
		response.Error = "Comment not specified"
		printResponse(response, rw, http.StatusOK)
		return
	} else if len(request.Message) > 100000 {
		response.Error = "Message too big"
		printResponse(response, rw, http.StatusOK)
		return
	}

	// avoid a form submission flood
	contactLimiter.Lock()
	if contactLimiter.i >= 30 {
		response.Error = "Too many messages"
		printResponse(response, rw, http.StatusOK)
		contactLimiter.Unlock()
		return
	} else {
		contactLimiter.i++
		contactLimiter.Unlock()
	}

	// send us an email - these emails are also auto-deleted after a ttl
	var to string
	var subj string
	if request.Route == "abuse" {
		to = config.AbuseMail
		subj = "DeleteBin Abuse Form Submission"
	} else if request.Route == "translate" {
		to = config.Mail
		subj = "DeleteBin Translate Form Submission"
	} else {
		to = config.Mail
		subj = "DeleteBin Contact Form Submission"
	}
	m := gomail.NewMessage()
	m.SetHeader("To", to)
	m.SetHeader("Subject", subj)
	m.SetHeader("From", config.Mail)
	if len(request.Email) > 3 && len(request.Email) < 254 && emailRX.MatchString(request.Email) {
		m.SetHeader("Reply-To", request.Email)
	}
	messageBody := "Name: " + request.Name + "\n\n" +
		"Email: " + request.Email + "\n\n" +
		"Message: " + request.Message + "\n\n" +
		"Client Details: " + req.Header.Get(config.RealIPHeader) + " / " + req.Header.Get("User-Agent")
	m.SetBody("text/plain", messageBody)

	// localhost is configured to properly send outbound over encrypted connection
	// email sent is encrypted all the way to the end recipient
	d := gomail.Dialer{Host: "localhost", Port: 25}
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	if err := d.DialAndSend(m); err != nil {
		response.Error = "Error sending"
		log.Println(err)
		printResponse(response, rw, http.StatusOK)
		return
	}
	response.Error = ""
	response.Result = struct {
		Sent bool
	}{
		true,
	}
	printResponse(response, rw, http.StatusOK)
}

// handles requests that are created when people click the report spam button on message retrieval
func spamHandler(rw http.ResponseWriter, req *http.Request) {
	response := &response{}
	if req.Method != "POST" {
		response.Error = "Only POST accepted"
		printResponse(response, rw, http.StatusInternalServerError)
		return
	}
	body, err := ioutil.ReadAll(req.Body) // upstream caps body size for us
	if err != nil {
		response.Error = "Communication error"
		printResponse(response, rw, http.StatusInternalServerError)
		return
	}
	if config.Debug {
		log.Println("spamHandler req: " + string(body))
	}
	var request struct {
		ID       string
		Comments string
	}
	err = json.Unmarshal(body, &request)

	// do we have valid input?
	if err != nil {
		if config.Debug {
			log.Println(err)
		}
		response.Error = "Malformed/invalid json"
		printResponse(response, rw, http.StatusOK)
		return
	} else if request.ID == "" {
		response.Error = "ID not specified"
		printResponse(response, rw, http.StatusOK)
		return
	}

	// avoid a form submission flood
	contactLimiter.Lock()
	if contactLimiter.i >= 30 {
		response.Error = "Too many messages"
		printResponse(response, rw, http.StatusOK)
		contactLimiter.Unlock()
		return
	} else {
		contactLimiter.i++
		contactLimiter.Unlock()
	}

	// update ip stats for sender of the possibly spam message
	var hashedIP string
	var created int64
	var ipr *ipRecord
	err = db.Update(func(txn *badger.Txn) error {

		// check for CT record first
		item, err := txn.Get([]byte(keyPrefixCT + request.ID))
		if err != nil {
			if err != badger.ErrKeyNotFound {
				return err
			}

			// check for RV record next
			item, err = txn.Get([]byte(keyPrefixRV + request.ID))
			if err != nil {
				return err
			} else {
				err = item.Value(func(val []byte) error {
					rvr := decodeRVRecord(val)
					hashedIP = rvr.HIP
					created = rvr.Created
					return nil
				})
				if err != nil {
					return err
				}
			}
		} else {

			// CT record still exists
			err = item.Value(func(val []byte) error {
				ctr := decodeCTRecord(val)
				hashedIP = ctr.HIP
				created = ctr.Created
				return nil
			})
			if err != nil {
				return err
			}
		}
		ipr, err = ipStats(txn, hashedIP, map[string]int{"Complaints": 1})
		return err
	})
	if err != nil {
		if err == badger.ErrKeyNotFound {
			response.Error = "Record not found"
			printResponse(response, rw, http.StatusOK)
		} else {
			// we need to know about this type of error
			log.Println(err) // should we bail here instead?
			response.Error = "Database error"
			printResponse(response, rw, http.StatusInternalServerError)
		}
		return
	}

	// send us an email - these emails are also auto-deleted after a ttl
	m := gomail.NewMessage()
	m.SetHeader("To", config.AbuseMail)
	m.SetHeader("Subject", "Spam Complaint")
	m.SetHeader("From", config.Mail)
	senderData := fmt.Sprintf("%+v\n", ipr)
	datetime := fmt.Sprint(time.Unix(created, 0))
	messageBody := "Comments: " + request.Comments + "\n\n" +
		"Message Sent: " + datetime + "\n\n" +
		"Message Sender Data: " + senderData + "\n\n" +
		"Client Details: " + req.Header.Get(config.RealIPHeader) + " / " + req.Header.Get("User-Agent")
	m.SetBody("text/plain", messageBody)

	// localhost is configured to properly send outbound over encrypted connection
	// email sent is encrypted all the way to the end recipient
	d := gomail.Dialer{Host: "localhost", Port: 25}
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	if err := d.DialAndSend(m); err != nil {
		response.Error = "Error sending"
		log.Println(err)
		printResponse(response, rw, http.StatusOK)
		return
	}
	response.Error = ""
	response.Result = struct {
		Sent bool
	}{
		true,
	}
	printResponse(response, rw, http.StatusOK)
}

// Set some rules for the client so they know what they must do to sSet - hands out number of required PBKDF2 iterations and deadline
// this is a precautionary step to offer some options to help prevent and deal with abuse/spam/etc.
// without relying on captchas... use up computer time instead of human time - but of course, this opens us up to
// abuse whereby someone could simply flood us from a "good" network to force real people to run more PBKDF2 iterations
// captchas may be inevitable if abuse ever becomes a major issue... but i hate captchas so we just increase PBKDF2 iterations for now
func sPreSetHandler(rw http.ResponseWriter, req *http.Request) {
	response := &response{}
	if req.Method != "POST" {
		response.Error = "Only POST accepted"
		printResponse(response, rw, http.StatusInternalServerError)
		return
	}

	// determine baseline iterations

	now := time.Now()
	var iter int64
	iter = 200000 // lowest possible iter count
	mrand.Seed(now.UnixNano())
	iter += int64(mrand.Intn(100000-1+1)) + 1

	// determine any additional iterations required due to client's previous actions - if any

	hashedIP := hashIP(req.Header.Get(config.RealIPHeader), stoHIPSecret(req)) // we set this value upstream
	err := db.View(func(txn *badger.Txn) error {
		ipr, err := ipStats(txn, hashedIP, nil)
		if err != nil {
			return err
		}

		// if this is the first time we are seeing this client, no need to do anything
		if ipr.Created == 0 {
			return nil
		}

		// if minimum RTLs have not yet been hit, no need to do anything
		if ipr.RTLs < config.RTLRRMinRange {
			return nil
		}

		// retrievals / total RTL ratio provides a good measurement to determine the spaminess of a source
		// a real sender would have real recipients and therefore that ratio should approach 1 over time
		// we use RTLs instead of Sets since they more accurately measure total possible recipients

		retrievalsToRTLs := float64(ipr.Retrievals) / float64(ipr.RTLs)
		var biggestRatio float64
		for ratio := range config.RTLRR {
			rratio := float64(ratio) * .01
			if rratio > retrievalsToRTLs && rratio > biggestRatio {
				biggestRatio = rratio
			}
		}
		if biggestRatio == 0 {
			biggestRatio = config.RTLRRMinRatio
		}
		biggestRatioI := int(biggestRatio * 100)
		var biggestRTLRange int
		for totalRTLs := range config.RTLRR[biggestRatioI] {
			if totalRTLs > ipr.RTLs && totalRTLs > biggestRTLRange {
				biggestRTLRange = totalRTLs
			}
		}
		addIters := config.RTLRR[biggestRatioI][biggestRTLRange]

		// TODO: there is probably a better way to incorporate complaint data, but for now, we just
		// multiply any extra iterations incurred due to the retrievals / total RTL ratio by the number
		// of complaints, if any

		if ipr.Complaints > 0 {
			addIters = addIters * int64(ipr.Complaints)
		}

		iter += addIters
		return nil
	})
	if err != nil {
		log.Println(err) // should we bail here instead?
		response.Error = "Database error"
		printResponse(response, rw, http.StatusInternalServerError)
		return
	}

	// a deadline is set to require the client to complete their Set within a reasonable time

	deadline := int(now.Unix() + 120) // they have 30 seconds to sSet

	hmac := hmac.New(sha256.New, hmacSecret.Bytes())
	_, err = hmac.Write([]byte(strconv.FormatInt(iter, 10) + strconv.Itoa(deadline)))
	if err != nil {
		log.Panicln(err)
	}
	response.Error = ""
	response.Result = struct {
		Iter     int64
		Deadline int
		HMAC     string
	}{
		iter,
		deadline,
		base64.RawURLEncoding.EncodeToString(hmac.Sum(nil)),
	}
	printResponse(response, rw, http.StatusOK)
}

// run the completion token by hcaptcha to verify authenticity
func hCaptchaVerify(token string) (bool, error) {
	var client = &http.Client{
		Timeout: time.Second * 10,
	}
	uv := url.Values{}
	uv.Set("secret", config.HCSecret)
	uv.Set("sitekey", config.HCSiteKey)
	uv.Set("response", token)
	payload := uv.Encode()
	req, err := http.NewRequest("POST", "https://hcaptcha.com/siteverify", strings.NewReader(payload))
	if err != nil {
		log.Panicln(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(payload)))
	if config.Debug {
		dump, _ := httputil.DumpRequestOut(req, true)
		log.Printf("%s\n\n", dump)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if config.Debug {
		dump, _ := httputil.DumpResponse(resp, true)
		log.Printf("%s\n\n", dump)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	var hcResp struct {
		ChallengeTS string   `json:"challenge_ts"`
		Hostname    string   `json:"hostname"`
		ErrorCodes  []string `json:"error-codes"`
		Success     bool     `json:"success"`
	}
	err = json.Unmarshal(body, &hcResp)
	if err != nil {
		return false, err
	}
	if config.Debug {
		log.Println("hcaptcha resp: ", hcResp)
	}
	if len(hcResp.ErrorCodes) > 0 {
		log.Println("hcaptcha errors", hcResp.ErrorCodes)
	}
	return hcResp.Success, nil
}

func printResponse(response *response, rw http.ResponseWriter, status int) {
	json, _ := json.Marshal(response)
	if config.Debug {
		log.Println("res: " + string(json))
	}
	rw.Header().Set("Content-Type", "application/json")
	// Since everything is POSTed - we should not need cache-control headers
	// But if we ever start allowing GETs, these will be needed
	//rw.Header().Set("Cache-Control", "no-cache, no-store, no-transform, must-revalidate, private, max-age=0")
	//rw.Header().Set("Pragma", "no-cache")
	rw.WriteHeader(status)
	rw.Write(json)
}

func main() {

	// Safely terminate in case of an interrupt signal
	memguard.CatchInterrupt()

	// Purge the session when we return
	defer memguard.Purge()

	// parse cli and config file input
	configPath := flag.String("config", "config.json", "path to JSON config file")
	flag.Parse()
	log.Println("config:", *configPath)
	configJSON, err := ioutil.ReadFile(*configPath)
	if err != nil {
		log.Panicln(err)
	}
	err = json.Unmarshal(configJSON, &config)
	if err != nil {
		log.Panicln(err)
	}
	log.Printf("%+v\n", config)

	// open database
	db, err = badger.Open(badger.DefaultOptions(config.DBPath))
	if err != nil {
		log.Panicln(err)
	}
	defer db.Close()

	// some housekeeping routines

	// triggers the garbage collection for BadgerDB
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
		again:
			err := db.RunValueLogGC(0.5) // https://godoc.org/github.com/dgraph-io/badger#DB.RunValueLogGC
			if err == nil {
				goto again
			}
		}
	}()

	// simply sets value to 0 - used to help stop DOS on contact forms
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			contactLimiter.Lock()
			contactLimiter.i = 0
			contactLimiter.Unlock()
		}
	}()

	// API endpoints

	mux := http.NewServeMux()

	// get ciphertext
	mux.HandleFunc("/sGet", sGetHandler)

	// dispenses iteration count + deadline
	mux.HandleFunc("/sPreSet", sPreSetHandler)

	// set ciphertext and return id
	mux.HandleFunc("/sSet", sSetHandler)

	// so people can get a hold of us
	mux.HandleFunc("/contact", contactHandler)

	// long-lost dear brother numsie wanting to send millions of dollars?
	mux.HandleFunc("/spam", spamHandler)

	// timeouts probably not needed since we sit behind a web server that sets its own limits
	// but would absolutely be required if we ran directly on public internet
	s := &http.Server{
		Addr:           config.Listen,
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 14,
	}
	log.Fatal(s.ListenAndServe())

}
