package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"database/sql"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// User represents a user in the system.
type User struct {
	UserID   string // Unique identifier for the user
	Username string // Username of the user
	Password string // Password of the user
}

// UserDataBase represents a collection of users and provides methods to manage them.
type UserDataBase struct {
	db *sql.DB
}

func NewUserDataBase(dbPath string) (*UserDataBase, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	createTableQuery := `
	CREATE TABLE IF NOT EXISTS users (
		user_id TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		password TEXT NOT NULL
	);
	`

	_, err = db.Exec(createTableQuery)
	if err != nil {
		return nil, err
	}

	return &UserDataBase{db: db}, nil
}

// validateUserInput validates the provided username and password.
func validateUserInput(username, password string) error {
	// Trim leading and trailing whitespace from inputs
	trimmedUsername := strings.TrimSpace(username)
	trimmedPassword := strings.TrimSpace(password)

	// Check if trimmed username is empty or consists only of whitespace
	if trimmedUsername == "" {
		return errors.New("username cannot be empty or consist only of whitespace")
	}

	// Check if trimmed password is empty or consists only of whitespace
	if trimmedPassword == "" {
		return errors.New("password cannot be empty or consist only of whitespace")
	}

	if len(password) < 8 {
		return errors.New("Password must be at least 8 characters long")
	}

	return nil
}

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 15)

	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
}

// addNewUser adds a new user to the database after validating inputs.
func (u *UserDataBase) addNewUser(username, password string) error {
	// Trim leading and trailing spaces from username and password
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)

	// Validate username and password
	if err := validateUserInput(username, password); err != nil {
		return err // Return error if validation fails
	}

	hashedPassword, err := hashPassword(password)

	if err != nil {
		fmt.Printf("Error hashing password: %s", err)
		return nil
	}

	var storedUsername string
	if err := u.db.QueryRow("SELECT username FROM users WHERE username = ?", username).Scan(&storedUsername); err == nil {
		return fmt.Errorf("user already exists")
	} else if err != sql.ErrNoRows {
		return err
	}

	// Generate UUID for the new user
	userID := uuid.New().String()

	insertUserQuery := `
	INSERT INTO users (user_id, username, password)
	VALUES (?, ?, ?);
	`

	if err != nil {
		return err
	}

	_, err = u.db.Exec(insertUserQuery, userID, username, hashedPassword)
	if err != nil {
		return err
	}

	// Print success message
	fmt.Printf("New user added: %s, UUID: %s\n", username, userID)
	return nil
}

func (u *UserDataBase) editUser(userID, newUsername, newPassword string) error {
	newUsername = strings.TrimSpace(newUsername)
	newPassword = strings.TrimSpace(newPassword)

	if err := validateUserInput(newUsername, newPassword); err != nil {
		return err
	}

	updateUserQuery := `
	UPDATE users 
	SET username = ?, password = ?
	WHERE user_id = ?;
	`

	newHashedPassowrd, err := hashPassword(newPassword)
	if err != nil {
		return err
	}

	_, err = u.db.Exec(updateUserQuery, newUsername, newHashedPassowrd, userID)
	if err != nil {
		return err
	}

	fmt.Printf("User with ID %s updated to %s\n", userID, newUsername)
	return nil
}

// listUsers lists all users in the database.
func (u *UserDataBase) listUsers() {
	fmt.Println("\nListing all users...")

	rows, err := u.db.Query("SELECT user_id, username FROM users;")
	if err != nil {
		fmt.Println("Error retrieving users: ", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var userID, username string
		if err := rows.Scan(&userID, &username); err != nil {
			fmt.Println("Error sdcanning user: ", err)
			continue
		}
		fmt.Printf("User: %s, ID: %s\n", username, userID)
	}

	if err := rows.Err(); err != nil {
		fmt.Println("Error interating over users: ", err)
	}

	fmt.Println()
}

func (u *UserDataBase) authenticateAdmin(username, password string) bool {
	var storedPassword string
	err := u.db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedPassword)

	if err != nil {
		return false
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))

	if err != nil {
		fmt.Printf("Error hashing password: %s", err)
		return false
	}

	return true
}

// Main function to run the user management program.
func main() {
	uDB, err := NewUserDataBase("users.db")
	if err != nil {
		fmt.Println("Error initializing database", err)
		return
	}
	defer uDB.db.Close()

	reader := bufio.NewReader(os.Stdin)

	adminLoggedIn := false

	choices := map[string]func(){
		"1": func() {
			fmt.Print("Enter username: ")
			username, _ := reader.ReadString('\n')
			fmt.Print("Enter password: ")
			password, _ := reader.ReadString('\n')

			username = strings.TrimSpace(username)
			password = strings.TrimSpace(password)

			if err := uDB.addNewUser(username, password); err != nil {
				fmt.Println("Error adding user: ", err)
			}
		},

		"2": func() {
			fmt.Print("Enter admin username: ")
			username, _ := reader.ReadString('\n')
			fmt.Print("Enter admin password: ")
			password, _ := reader.ReadString('\n')

			username = strings.TrimSpace(username)
			password = strings.TrimSpace(password)

			if uDB.authenticateAdmin(username, password) {
				adminLoggedIn = true
				fmt.Println("Admin logged successfully.")

			} else {
				fmt.Println("Invalid admin credentials.")
			}
		},

		"3": func() {
			if !adminLoggedIn {
				fmt.Println("Admin login required to edit users")
				return
			}

			fmt.Print("Enter user ID to edit: ")
			userID, _ := reader.ReadString('\n')

			userID = strings.TrimSpace(userID)

			fmt.Print("Enter new username: ")
			newUsername, _ := reader.ReadString('\n')
			fmt.Print("Enter new password: ")
			newPassword, _ := reader.ReadString('\n')

			newUsername = strings.TrimSpace(newUsername)
			newPassword = strings.TrimSpace(newPassword)

			if err := uDB.editUser(userID, newUsername, newPassword); err != nil {
				fmt.Println("Error while editing user: ", err)
			}
		},

		"4": func() {
			uDB.listUsers()
		},

		"5": func() {
			fmt.Print("\nExiting program...")
			os.Exit(0)
		},
	}

	for {
		fmt.Println("Menu = {")
		fmt.Println("    1. Add New User")
		fmt.Println("    2. Admin panel")
		fmt.Println("    3. Edit Existing User")
		fmt.Println("    4. List Users")
		fmt.Println("    5. Exit")
		fmt.Println("}\n")

		fmt.Print("Enter your choice: ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		if action, exist := choices[choice]; exist {
			action()
		} else {
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}
