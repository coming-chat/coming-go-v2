package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	textsecure "github.com/coming-chat/coming-go-v2"
	"github.com/coming-chat/coming-go-v2/database/mongo"
	"github.com/coming-chat/coming-go-v2/database/psql"
	cache "github.com/coming-chat/coming-go-v2/redis"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/coming-chat/coming-go-v2/axolotl"
	"github.com/coming-chat/coming-go-v2/config"
	"github.com/coming-chat/coming-go-v2/contacts"
	"golang.org/x/crypto/ssh/terminal"

	log "github.com/sirupsen/logrus"
)

// Simple command line test app for TextSecure.
// It can act as an echo service, send one-off messages and attachments,
// or carry on a conversation with another client,
// or send all messages received to redis

var (
	echo                bool
	to                  string
	group               bool
	message             string
	attachment          string
	newgroup            string
	updategroup         string
	leavegroup          string
	endsession          bool
	showdevices         bool
	linkdevice          string
	unlinkdevice        int
	configDir           string
	stress              int
	hook                string
	raw                 bool
	gateway             bool
	bind                string
	redismode           bool
	redisbind           string
	redispw             string
	redisdb             int
	redisMsgRecTopic    string
	redisMsgReplyTopic  string
	redisMsgReplyGroup  string
	useGroup            bool
	signInOrUp          bool
	postgresMode        bool
	postgresUrl         string
	mongoMode           bool
	mongoUrl            string
	limitedCid          int
	sendMessagePoolSize int64
	handleMsgSize       int64
)

func init() {
	flag.BoolVar(&echo, "echo", false, "Act as an echo service")
	flag.StringVar(&to, "to", "", "Contact name to send the message to")
	flag.BoolVar(&group, "group", false, "Destination is a group")
	flag.StringVar(&message, "message", "", "Single message to send, then exit")
	flag.StringVar(&attachment, "attachment", "", "File to attach")
	flag.StringVar(&newgroup, "newgroup", "", "Create a group, the argument has the format 'name:member1:member2'")
	flag.StringVar(&updategroup, "updategroup", "", "Update a group, the argument has the format 'hexid:name:member1:member2'")
	flag.StringVar(&leavegroup, "leavegroup", "", "Leave a group named by the argument")
	flag.BoolVar(&endsession, "endsession", false, "Terminate session with peer")
	flag.BoolVar(&showdevices, "showdevices", false, "Show linked devices")
	flag.StringVar(&linkdevice, "linkdevice", "", "Link a new device, the argument is a url in the format 'sgn:/?uuid=xxx&pub_key=yyy'")
	flag.IntVar(&unlinkdevice, "unlinkdevice", 0, "Unlink a device, the argument is the id of the device to delete")
	flag.IntVar(&stress, "stress", 0, "Automatically send many messages to the peer")
	flag.StringVar(&configDir, "config", ".config", "Location of config dir")
	flag.StringVar(&hook, "hook", "", "Program/Script to call when message is received (e.g. for bot usage)")
	flag.BoolVar(&raw, "raw", false, "raw mode, disable ansi colors")
	flag.BoolVar(&gateway, "gateway", false, "http gateway mode")
	flag.StringVar(&bind, "bind", "localhost:5000", "bind address and port when in gateway-mode")
	flag.BoolVar(&redismode, "redismode", false, "redis mode")
	flag.StringVar(&redisbind, "redisbind", "redis:6379", "bind address and port for redis")
	flag.StringVar(&redispw, "redispw", "", "redis password")
	flag.IntVar(&redisdb, "redisdb", 0, "redis database")
	flag.StringVar(&redisMsgRecTopic, "redismrect", "", "receive message push to redis topic")
	flag.StringVar(&redisMsgReplyTopic, "redismrelt", "", "listen topic to push message")
	flag.StringVar(&redisMsgReplyGroup, "redismrg", "coming-go", "listen topic group name")
	flag.BoolVar(&useGroup, "usegroup", false, "use group ?")
	flag.BoolVar(&signInOrUp, "signinorup", false, "sign in is true, sign up is false")
	flag.BoolVar(&postgresMode, "psqlmode", false, "save message in postgresDB")
	flag.StringVar(&postgresUrl, "psqlurl", "", "postgres url")
	flag.BoolVar(&mongoMode, "mongomode", false, "save message in mongo")
	flag.StringVar(&mongoUrl, "mongourl", "", "mongo url")
	flag.IntVar(&limitedCid, "limitedcid", 13, "limited length of cid can be call")
	flag.Int64Var(&sendMessagePoolSize, "sendmsgpoolsize", 1, "send message pool size")
	flag.Int64Var(&handleMsgSize, "handlemsize", 1, "handle message betch size")
}

var (
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	blue   = "\x1b[34m"
)

func readLine(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	text, _, err := reader.ReadLine()
	if err != nil {
		log.Fatal("Cannot read line from console: ", err)
	}
	return string(text)
}

func getCaptchaToken() string {
	log.Infoln("1. Goto https://signalcaptchas.org/registration/generate.html")
	log.Infoln("2. Run the interception code in the browser terminal.")
	log.Infoln("window.onToken = function(token){alert(token);};")
	log.Infoln("3. Solve captcha and copy the token from the alert.")

	return readLine("4. Enter captcha token>")
}
func getPhoneNumber() string {
	return readLine("Enter Phone number beginning with + and country code like +44...>")
}
func getPin() string {
	return readLine("Enter Pin>")
}
func getVerificationCode() string {
	return readLine("Enter verification code>")
}

func getStoragePassword() string {
	fmt.Printf("Input storage password>")
	password, err := terminal.ReadPassword(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println()
	return string(password)
}

func getConfig() (*config.Config, error) {
	return textsecure.ReadConfig(configDir + "/config.yml")
}
func getLocalContacts() ([]contacts.Contact, error) {
	return contacts.ReadContacts(configDir + "/contacts.yml")
}

func getAvatarPath() string {
	return readLine("get avatar local path> ")
}

func sendMessage(isGroup bool, to, message string) error {
	var err error
	if isGroup {
		_, err = textsecure.SendGroupMessage(to, message, 0) // 0 is the expire timer
	} else {
		_, err = textsecure.SendMessage(to, message, 0)
		if nerr, ok := err.(axolotl.NotTrustedError); ok {
			fmt.Printf("Peer identity not trusted. Remove the file .storage/identity/remote_%s to approve\n", nerr.ID)
		}
	}
	return err
}

func sendAttachment(isGroup bool, to, message string, f io.Reader) error {
	var err error
	if isGroup {
		_, err = textsecure.SendGroupAttachment(to, message, f, 0)
	} else {
		_, err = textsecure.SendAttachment(to, message, f, 0)
		if nerr, ok := err.(axolotl.NotTrustedError); ok {
			fmt.Printf("Peer identity not trusted. Remove the file .storage/identity/remote_%s to approve\n", nerr.ID)
		}
	}
	return err
}

// conversationLoop sends messages read from the console
func conversationLoop(isGroup bool) {
	for {
		var message string
		if raw {
			message = readLine(fmt.Sprintf(""))
		} else {
			message = readLine(fmt.Sprintf("%s>", blue))
		}
		if message == "" {
			continue
		}

		err := sendMessage(isGroup, to, message)

		if err != nil {
			log.Error(err)
		}
	}
}

func receiptMessageHandler(msg *textsecure.Message) {
}
func typingMessageHandler(msg *textsecure.Message) {
	log.Infoln("user " + msg.Source + " is " + msg.Message)
}
func callMessageHandler(msg *textsecure.Message) {
}
func syncSentHandler(msg *textsecure.Message, id uint64) {
}
func syncReadHandler(text string, id uint64) {
}

func messageHandler(msg *textsecure.Message) {
	if len(msg.Source) > limitedCid {
		err := sendMessage(msg.Group != nil, msg.Source, "Sorry, you are temporarily unable to usethis feature. lf you use a 3, 4, 5 or 6-digitCID to log in to ComingChat, I can chatwith you and help answer yourquestions.")
		if err != nil {
			log.Error(err)
		}
		return
	}
	if echo {
		to := msg.Source
		if msg.Group != nil {
			to = msg.Group.Hexid
		}
		err := sendMessage(msg.Group != nil, to, msg.Message)

		if err != nil {
			log.Error(err)
		}
		return
	}

	if msg.Message != "" {
		fmt.Printf("\r%s\n>", pretty(msg))
		if hook != "" {
			hookProcess := exec.Command(hook, pretty(msg))
			hookProcess.Start()
			hookProcess.Wait()
		}
		if !raw {
			fmt.Printf("\r%s\n>", pretty(msg))
		}
	} else if len(msg.Attachments) != 0 {
		err := sendMessage(msg.Group != nil, msg.Source, "Non-text is not supported, please re-describe your question.")
		if err != nil {
			log.Error(err)
		}
		return
	} else {
		return
	}

	for _, a := range msg.Attachments {
		handleAttachment(msg.Source, a.R)
	}

	// if no peer was specified on the command line, start a conversation with the first one contacting us
	if to == "" {
		to = msg.Source
		isGroup := false
		if msg.Group != nil {
			isGroup = true
			to = msg.Group.Hexid
		}
		if !redismode {
			go conversationLoop(isGroup)
		}
	}

	_, err := textsecure.SendReceiptMessage(msg.Source, map[textsecure.ReceiptTpe][]uint64{
		textsecure.DELIVERY: {msg.Timestamp},
	})
	if err != nil {
		log.Errorf("send DELIVERY message failed: %v", err)
	}
	if postgresMode && !mongoMode {
		err = psql.DB.SavaReceiveMessage(msg.Source, msg.SourceUUID, msg.Message, int64(msg.Timestamp), msg.GroupV2, msg.Quote)
		if err != nil {
			log.Errorf("save message %v on db err: %v", msg, err)
		}
	}
	if mongoMode {
		err = mongo.DB.SavaReceiveMessage(msg.Source, msg.SourceUUID, msg.Message, int64(msg.Timestamp), msg.GroupV2, msg.Quote)
		if err != nil {
			log.Errorf("save message %v on db err: %v", msg, err)
		}
	}
	if redismode {
		log.Infof("Publishing to redis, To: %s, Msg: %s", to, msg.Message)

		cache.SendMessageToRedis(redisMsgRecTopic, msg.Message, msg.Source, msg.SourceUUID, msg.Timestamp, msg.GroupV2, msg.Quote)
	}
	_, err = textsecure.SendReceiptMessage(msg.Source, map[textsecure.ReceiptTpe][]uint64{
		textsecure.READ: {msg.Timestamp},
	})
	if err != nil {
		log.Errorf("send READ message failed: %v", err)
	}
	_, err = textsecure.SendTypingStartMessage(msg.Source)
	if err != nil {
		log.Errorf("send typing start message failed: %v", err)
	}
}

func handleAttachment(src string, r io.Reader) {
	f, err := ioutil.TempFile(".", "TextSecure_Attachment")
	if err != nil {
		log.Error(err)
		return
	}
	l, err := io.Copy(f, r)
	if err != nil {
		log.Error(err)
		return
	}
	log.Infof("Saving attachment of length %d from %s to %s", l, src, f.Name())
}

var timeFormat = "Mon 03:04"

func timestamp(msg *textsecure.Message) string {
	t := time.Unix(0, int64(msg.Timestamp)*1000000)
	return t.Format(timeFormat)
}

func pretty(msg *textsecure.Message) string {
	src := getName(msg.Source)
	if msg.Group != nil {
		src = src + "[" + msg.Group.Name + "]"
	}
	if raw {
		return fmt.Sprintf("%s %s %s", timestamp(msg), src, msg.Message)
	}
	return fmt.Sprintf("%s %s %s", timestamp(msg), src, msg.Message)
}

// getName returns the local contact name corresponding to a phone number,
// or failing to find a contact the phone number itself
func getName(tel string) string {
	if n, ok := telToName[tel]; ok {
		return n
	}
	return tel
}

func registrationDone() {
	log.Info("Registration done.")
}

// GroupFile loads group info from file
type GroupFile struct {
	ID      []byte
	Hexid   string
	Flags   uint32
	Name    string
	Members []string
	Avatar  io.Reader `yaml:"-"`
}

// Group as json object for output
type Group struct {
	Name string `json:"name"`
}

// GroupsHandler will return all known groups as json
func GroupsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	data := make(map[string]Group)

	filepath.Walk(".storage/groups", func(path string, info os.FileInfo, e error) error {
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			group := &GroupFile{}
			err = yaml.Unmarshal(b, group)
			if err != nil {
				return err
			}
			data[group.Hexid] = Group{Name: group.Name}
		}
		return nil
	})
	json.NewEncoder(w).Encode(data)
}

// RekeyHandler will delete existing peer identity
func RekeyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "DELETE" {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "{\"success\": false}")
		return
	}

	identity := r.URL.Path[len("/rekey/"):]
	isIdentity := regexp.MustCompile(`^\d*$`).MatchString(identity)
	if isIdentity {
		filename := []string{".storage/identity/remote", identity}
		err := os.Remove(strings.Join(filename, "_"))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "{\"success\": false, \"error\": \"identity %s not found\"}", identity)
			return
		}
		fmt.Fprintf(w, "{\"success\": true}")
		return
	}
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, "{\"success\": false}")
	return
}

// GatewaySend sends pre-processed messages
func GatewaySend(to string, message string, filename string) (bool, string) {
	var errormessage string
	var err error
	isGroup := regexp.MustCompile(`^([a-f\d]{64})$`).MatchString(to)
	if filename != "" {
		f, fErr := os.Open(filename)
		if fErr != nil {
			return false, fErr.Error()
		}
		err = sendAttachment(isGroup, to, message, f)
		os.Remove(filename)
	} else {
		err = sendMessage(isGroup, to, message)
	}
	if err != nil {
		switch {
		case regexp.MustCompile(`status code 413`).MatchString(err.Error()):
			errormessage = "signal api rate limit reached"
		case regexp.MustCompile(`remote identity \d+ is not trusted`).MatchString(err.Error()):
			errormessage = "remote identity "
			errormessage += to
			errormessage += " is not trusted"
		default:
			errormessage = strings.Trim(err.Error(), "\n")
		}
		return false, errormessage
	}
	return true, "OK"
}

// JSONHandler to receive POST json request, process and send
func JSONHandler(w http.ResponseWriter, r *http.Request) {
	messageField := os.Getenv("JSON_MESSAGE")
	if messageField == "" {
		messageField = "message"
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error("Error: ", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "{\"success\": false}")
		return
	}
	var data map[string]interface{}
	result := json.Unmarshal([]byte(body), &data)
	if result != nil {
		log.Error("Error: ", result.Error())
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "{\"success\": false}")
		return
	}
	message := data[messageField]
	if message == nil {
		log.Error("Error: json request contains empty item ", messageField)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "{\"success\": false, \"error\": \"json request contains empty item %s\"}", messageField)
		return
	}
	to := r.URL.Path[len("/json/"):]
	sendError, errormessage := GatewaySend(to, message.(string), "")
	if sendError == false {
		log.Error("Error: ", errormessage)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "{\"success\": false, \"error\": \"%s\"}", errormessage)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "{\"success\": true}")
	return
}

// GatewayHandler to receive POST form data, process and send
func GatewayHandler(w http.ResponseWriter, r *http.Request) {

	filename := ""

	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		log.Error("Error: requires POST request")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "{\"success\": false}")
		return
	}

	message := r.FormValue("message")
	to := r.FormValue("to")
	file, header, err := r.FormFile("file")
	if err == nil {
		defer file.Close()
		f, err := os.OpenFile("/tmp/"+header.Filename, os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			log.Error("Error: ", err.Error())
		} else {
			filename = "/tmp/" + header.Filename
		}
		defer f.Close()
		io.Copy(f, file)
	}

	if len(message) > 0 && len(to) > 0 {
		sendError := false
		errormessage := "OK"
		if filename != "" {
			sendError, errormessage = GatewaySend(to, message, filename)
		} else {
			sendError, errormessage = GatewaySend(to, message, "")
		}
		if sendError == false {
			log.Error("Error: ", errormessage)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "{\"success\": false, \"error\": \"%s\"}", errormessage)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "{\"success\": true}")
		return
	}
	log.Error("Error: form fields message and to are required")
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, "{\"success\": false, \"error\": \"form fields message and to are required\"}")
	return
}

var telToName map[string]string

func main() {
	flag.Parse()
	textsecure.UseGroup = useGroup
	client := &textsecure.Client{
		GetConfig:             getConfig,
		GetLocalContacts:      getLocalContacts,
		GetCaptchaToken:       getCaptchaToken,
		GetVerificationCode:   getVerificationCode,
		GetStoragePassword:    getStoragePassword,
		MessageHandler:        messageHandler,
		ReceiptMessageHandler: receiptMessageHandler,
		RegistrationDone:      registrationDone,
		GetPhoneNumber:        getPhoneNumber,
		GetPin:                getPin,
		TypingMessageHandler:  typingMessageHandler,
		CallMessageHandler:    callMessageHandler,
		SyncReadHandler:       syncReadHandler,
		SyncSentHandler:       syncSentHandler,
		GetAvatarPath:         getAvatarPath,
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	if postgresMode {
		err := psql.NewDB(postgresUrl)
		if err != nil {
			log.Fatal(err)
		}
	}

	if mongoMode {
		err := mongo.New(mongoUrl, ctx)
		if err != nil {
			log.Fatal(err)
		}
	}

	err := textsecure.Setup(client, signInOrUp)
	if err != nil {
		log.Fatal(err)
	}

	if gateway {
		http.HandleFunc("/", GatewayHandler)
		http.HandleFunc("/groups", GroupsHandler)
		http.HandleFunc("/rekey/", RekeyHandler)
		http.HandleFunc("/json/", JSONHandler)
		go func() {
			log.Fatal(http.ListenAndServe(bind, nil))
		}()
	}

	if linkdevice != "" {
		log.Infof("Linking new device with url: %s", linkdevice)
		url, err := url.Parse(linkdevice)
		if err != nil {
			log.Fatal(err)
		}

		uuid := url.Query().Get("uuid")
		pk := url.Query().Get("pub_key")
		code, err := textsecure.NewDeviceVerificationCode()
		if err != nil {
			log.Fatal(err)
		}

		err = textsecure.AddDevice(uuid, pk, code)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	if unlinkdevice > 0 {
		err = textsecure.UnlinkDevice(unlinkdevice)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	if showdevices {
		devs, err := textsecure.LinkedDevices()
		if err != nil {
			log.Fatal(err)
		}

		for _, d := range devs {
			log.Infof("ID: %d\n", d.ID)
			log.Infof("Name: %s\n", d.Name)
			log.Infof("Created: %d\n", d.Created)
			log.Infof("LastSeen: %d\n", d.LastSeen)
			log.Info("============")
		}
		return
	}

	if !echo {
		//contacts, err := textsecure.GetRegisteredContacts()
		//if err != nil {
		//	log.Infof("Could not get contacts: %s", err)
		//}

		//telToName = make(map[string]string)
		//for _, c := range contacts {
		//	telToName[c.Tel] = c.Name
		//}

		if newgroup != "" {
			s := strings.Split(newgroup, ":")
			textsecure.NewGroup(s[0], s[1:])
			return
		}
		if updategroup != "" {
			s := strings.Split(updategroup, ":")
			textsecure.UpdateGroup(s[0], s[1], s[2:])
			return
		}
		if leavegroup != "" {
			textsecure.LeaveGroup(leavegroup)
			return
		}
		//If "to" matches a contact name then get its phone number, otherwise assume "to" is a phone number
		//for _, c := range contacts {
		//	if strings.EqualFold(c.Name, to) {
		//		to = c.UUID
		//		break
		//	}
		//}

		if to != "" {
			// Terminate the session with the peer
			if endsession {
				textsecure.EndSession(to, "TERMINATE")
				return
			}

			// Send attachment with optional message then exit
			if attachment != "" {
				f, err := os.Open(attachment)
				if err != nil {
					log.Fatal(err)
				}

				err = sendAttachment(group, to, message, f)
				if err != nil {
					log.Fatal(err)
				}
				return
			}

			if stress > 0 {
				c := make(chan int, stress)
				for i := 0; i < stress; i++ {
					go func(i int) {
						sendMessage(false, to, fmt.Sprintf("Stress %d\n", i))
						c <- i
					}(i)
				}
				for i := 0; i < stress; i++ {
					<-c
				}
				return
			}

			// Send a message then exit
			if message != "" {
				err := sendMessage(group, to, message)
				if err != nil {
					log.Fatal(err)
				}
				return
			}

			// Enter conversation mode
			go conversationLoop(group)
		}
	}

	if redismode {
		err := cache.NewClient(redisbind, redispw, redisdb)
		if err != nil {
			log.Fatal(err)
		}
		cache.SendMsgPoolSize = int64(sendMessagePoolSize)
		cache.HandleMsgSize = handleMsgSize
		cache.ListenTopic = redisMsgReplyTopic
		cache.GroupId = redisMsgReplyGroup
		err = cache.InitCustomer()
		if err != nil {
			log.Fatal(err)
		}
		defer cache.Wg.Wait()

		go cache.ListenMessage(ctx)
	}

	go func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				err = textsecure.StartListening(ctx)
				if err != nil {
					log.Error(err)
				}
			}

		}
	}(ctx)

	interrupt := make(chan os.Signal, 1)

	for {
		signal.Notify(interrupt, os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT)
		select {
		case <-interrupt:
			log.Infoln("[closing] signal get, start close")
			return
		default:
			continue
		}
	}

}
