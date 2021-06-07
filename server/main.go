package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type reminder struct {
	ID          int32  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Time        string `json:"time"` // Unix time in seconds
	// Positive numbers represent length in days (max: 364),
	// negative numbers represent months (max: 11),
	// Repeat >= 365 or Repeat <= -12 represents 1 year (max time is 1 year)
	// 0 means no repeat
	Repeat int32 `json:"repeat"`
	// 0 means incomplete and an email hasn't been sent
	// -1 means incomplete and an email HAS been sent
	// 1 means complete
	Completed int32 `json:"completed"`
}

const (
	ip   = "localhost"
	port = "8765"
)

var (
	logger *log.Logger
	db     *sql.DB
	dbMut  sync.RWMutex
)

func main() {
	f, err := os.Create("server.log")
	if err != nil {
		log.Fatal(err)
	}
	logger = log.New(f, "", log.LstdFlags|log.Lshortfile)

	if db, err = sql.Open("sqlite3", "reminders.db"); err != nil {
		logger.Panic(err)
	}

	handleReminders()

	server := &http.Server{
		Addr: ip + ":" + port,
		Handler: func() *http.ServeMux {
			r := http.NewServeMux()
			r.HandleFunc("/", pageHandler)
			r.HandleFunc("/reminders", remindersHandler)
			r.HandleFunc("/login", loginHandler)
			return r
		}(),
		ErrorLog: logger,
	}
	logger.Panic(server.ListenAndServe())
}

// pageHandler servers the web page
func pageHandler(w http.ResponseWriter, r *http.Request) {
	if ts, err := template.ParseFiles("index.html"); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println(err)
	} else if err = ts.Execute(w, nil); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println(err)
	}
}

// remindersHandler handles reminder retrieval, creation, updating, and deletion
func remindersHandler(w http.ResponseWriter, r *http.Request) {
	/* TODO: Use session or JWT */
	email := ""
	if r.Method == http.MethodGet {
		/* TODO: Handle errors from query */
		// Get reminder(s)
		stmt := fmt.Sprintf(`SELECT * FROM [%s] WHERE completed < 1`, email)
		dbMut.RLock()
		rows, err := db.Query(stmt)
		dbMut.RUnlock()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Println(err)
			return
		}
		defer rows.Close()
		var rmdrs []*reminder
		for rows.Next() {
			var rmdr *reminder
			if err := rows.Scan(rmdr.Name, rmdr.Description, rmdr.Time, rmdr.Repeat, rmdr.Completed); err != nil {
				logger.Println(err)
				continue
			}
			rmdrs = append(rmdrs, rmdr)
		}
		if rows.Err() != nil {
			logger.Println(err)
		}
		if rmdrs != nil {
			if err := json.NewEncoder(w).Encode(&rmdrs); err != nil {
				logger.Println(err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		} else {
			if rows.Err() != nil {
				http.Error(w, "Error retrieving reminders", http.StatusInternalServerError)
			} else {
				/* TODO: Figure out what to do with no reminders */
				w.Write([]byte(""))
			}
		}
	} else if r.Method == http.MethodPost {
		// Add reminder
		var rmdr *reminder
		if err := json.NewDecoder(r.Body).Decode(rmdr); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Println(err)
			return
		}
		stmt := `INSERT INTO reminders (name, description, time, repeat, completed) VALUES (?,?,?,?,?)`
		dbMut.Lock()
		defer dbMut.Unlock()
		_, err := db.Exec(stmt, rmdr.Name, rmdr.Description, rmdr.Time, rmdr.Repeat, rmdr.Completed)
		if err != nil {
			http.Error(w, "Error saving reminder", http.StatusInternalServerError)
			logger.Println(err)
		}
	} else if r.Method == http.MethodPut {
		// Update reminder
	} else if r.Method == http.MethodDelete {
		// Delete reminder
		strID := r.FormValue("id")
		if strID == "" {
			http.Error(w, "Must provide reminder id", http.StatusBadRequest)
			return
		}
		id, err := strconv.Atoi(strID)
		if err != nil {
			http.Error(w, "Invalid number", http.StatusBadRequest)
			return
		}
		stmt := fmt.Sprintf(`DELETE FROM [%s] WHERE name=%d`, email, id)
		dbMut.Lock()
		defer dbMut.Unlock()
		if _, err := db.Exec(stmt); err != nil {
			http.Error(w, "Error deleting reminder", http.StatusInternalServerError)
			logger.Println(err)
		}
	}
}

// loginHandler handles login and registration
func loginHandler(w http.ResponseWriter, r *http.Request) {
	//
}

// handleReminders sends emails whenever it's time for a reminder
// and updates the time of the reminder if it's repeated
func handleReminders() {
	timerLength := time.Minute
	var timer *time.Timer
	timer = time.AfterFunc(timerLength, func() {
		defer timer.Reset(timerLength)
		dbMut.RLock()
		emails, err := db.Query(`SELECT email FROM users`)
		dbMut.RUnlock()
		if err != nil {
			/* TODO: Handle error better */
			logger.Println(err)
		}
		for emails.Next() {
			var email string
			if err := emails.Scan(&email); err != nil {
				/* Include table name (email) */
				logger.Println(err)
				continue
			}
			dbMut.RLock()
			rmdrs, err := db.Query(`SELECT * FROM [?]`, email)
			dbMut.RUnlock()
			if err != nil {
				/* IDEA: reassign stmt */
				logger.Println(err)
				continue
			}
			// Loop through the reminders associated with the account
			for rmdrs.Next() {
				var name, description string
				var id, repeat, completed int32
				var utime int64
				if err := rmdrs.Scan(&id, &name, &description, &utime, &repeat, &completed); err != nil {
					logger.Println(err)
					continue
				}
				t := time.Unix(utime, 0)
				if completed == 0 {
					// Send email if time for reminder
					if time.Now().After(t) {
						/* TODO: Send email */
						stmt := fmt.Sprintf(`UPDATE [%s] SET completed=%d WHERE id=%d`, email, -1, id)
						_, err := db.Exec(stmt)
						if err != nil {
							logger.Println(err)
						}
					}
				}
				if repeat != 0 {
					//
				}
			}
			if rmdrs.Err() != nil {
				logger.Println(rmdrs.Err())
			}
		}
		if emails.Err() != nil {
			logger.Println(emails.Err())
		}
	})
}

/* TODO: Include user email when logging errors */

type user struct{}

var (
	errAccountExists      = errors.New("email already associated with account")
	errAccountDoesntExist = errors.New("no account associated with email")
	errIncorrectPassword  = errors.New("incorrect password")
)

func hashPassword(password string) (string, error) {
	bpass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bpass), err
}

func createUser(email, password string) error {
	hashed, err := hashPassword(password)
	if err != nil {
		logger.Println(err)
		return errors.New("error creating user")
	}
	dbMut.Lock()
	defer dbMut.Unlock()
	if _, err = db.Exec(`INSERT INTO users VALUES (?,?)`, email, hashed); err != nil {
		if strings.Contains(err.Error(), "unique") {
			return errAccountExists
		}
		logger.Println(err)
		return errors.New("error creating user")
	}
	return nil
}

func getUser(email, password string) (*user, error) {
	dbMut.RLock()
	defer dbMut.RUnlock()
	row := db.QueryRow(`SELECT password FROM users WHERE email=?`, email)
	var hashed string
	if err := row.Scan(&hashed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errAccountDoesntExist
		}
		logger.Println(err)
		return nil, errors.New("error getting user")
	}
	if bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)) == nil {
		return &user{}, nil
	}
	return nil, errIncorrectPassword
}

func deleteUser(email, password string) error {
	dbMut.Lock()
	defer dbMut.Unlock()
	res, err := db.Exec(`DELETE FROM users WHERE email=? AND password=?`, email, password)
	if err != nil {
		logger.Println(err)
		return errors.New("error deleting user")
	}
	if deleted, err := res.RowsAffected(); err != nil {
		/* TODO: figure out what an error here means */
		logger.Println(err)
		return errors.New("error deleting user")
	} else if deleted == 0 {
		return errAccountDoesntExist
	}
	if _, err = db.Exec(fmt.Sprintf(`DROP TABLE [%s]`, email)); err != nil {
		logger.Println(err)
		return errors.New("error deleting user")
	}
	return nil
}
