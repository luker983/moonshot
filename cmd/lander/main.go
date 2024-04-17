package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"github.com/quasoft/memstore"
)

var (
	sessionSecret = os.Getenv("LANDER_SECRET")
	adminPassword = os.Getenv("LANDER_ADMIN_PASS")
	flag          = os.Getenv("LANDER_FLAG")
)

var store sessions.Store
var users = map[string]string{
	"admin":     adminPassword,
	"anonymous": "",
}

func main() {
	var err error

	if sessionSecret == "" || adminPassword == "" || flag == "" {
		log.Fatal("must set env variables")
	}

	store, err = LoadStore()
	if err != nil {
		log.Fatal(err)
	}

	fs := http.FileServer(http.Dir("./site"))
	http.Handle("/", fs)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/logout", LogoutHandler)
	http.HandleFunc("/data", DataHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func LoadStore() (sessions.Store, error) {
	var err error
	store, err = loadMemStore()
	if err != nil {
		return nil, err
	}
	return store, nil
}

func loadMemStore() (sessions.Store, error) {
	return memstore.NewMemStore([]byte(sessionSecret)), nil
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	user := r.URL.Query().Get("user")
	pass := r.URL.Query().Get("pass")
	updateSession(session, "user", user, r, w)

	password, ok := users[user]
	if !ok {
		updateSession(session, "user", "anonymous", r, w)
		http.Error(w, "invalid user", http.StatusUnauthorized)
		return
	}

	if subtle.ConstantTimeCompare([]byte(pass), []byte(password)) == 0 {
		updateSession(session, "user", "anonymous", r, w)
		http.Error(w, "invalid password", http.StatusUnauthorized)
		return
	}

	w.Write([]byte(fmt.Sprintf("user=%s", session.Values["user"])))
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	updateSession(session, "user", "anonymous", r, w)
	w.Write([]byte(fmt.Sprintf("user=%s", session.Values["user"])))
}

type Telemetry struct {
	Temp      int
	Battery   int
	Healthy   bool
	Latitude  float32
	Longitude float32
	Flag      string
}

func DataHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Telemetry{
		Temp:      rand.Intn(289) - 183,
		Battery:   rand.Intn(100),
		Healthy:   false,
		Latitude:  -43.4,
		Longitude: -11.4,
		Flag: func() string {
			session, _ := store.Get(r, "session")
			if session.Values["user"] == "admin" {
				return flag
			}
			return "access denied"
		}(),
	})
}

func updateSession(session *sessions.Session, key, value any, r *http.Request, w http.ResponseWriter) {
	session.Values[key] = value
	session.Save(r, w)
}
