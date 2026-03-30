package main

import (
    "crypto/rand"
    "database/sql"
    "encoding/hex"
    "log"
    "net/http"
    "os" // <-- 🟢 NEW: Required to read Cloud variables!
    "sync"

    "github.com/gin-gonic/gin"
    "github.com/gorilla/websocket"
    _ "github.com/lib/pq"
    "golang.org/x/crypto/bcrypt" 
)

var db *sql.DB

var clients = make(map[string]*websocket.Conn)
var clientsMutex sync.Mutex

var sessions = make(map[string]string)
var sessionMutex sync.Mutex

var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        return true
    },
}

type Message struct {
    From    string `json:"from"`
    To      string `json:"to"`
    Message string `json:"message"`
}

func generateWingID() string {
    bytes := make([]byte, 6)
    rand.Read(bytes)
    id := hex.EncodeToString(bytes)
    return "WNG-" + id
}

func connectDB() {
    // Look for a cloud database first. If empty, use the local one.
    connStr := os.Getenv("DATABASE_URL")
    if connStr == "" {
        connStr = "host=localhost user=wingsuser password=wingspass dbname=wingsconnect sslmode=disable"
    }

    var err error
    db, err = sql.Open("postgres", connStr)
    if err != nil {
        log.Fatal(err)
    }

    err = db.Ping()
    if err != nil {
        log.Fatal("Database connection failed")
    }

    // --- 🟢 NEW: AUTO-BUILD CLOUD TABLES 🟢 ---
    createUsersTable := `
    CREATE TABLE IF NOT EXISTS users (
        wing_id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        public_key TEXT,
        avatar TEXT
    );`
    _, err = db.Exec(createUsersTable)
    if err != nil { log.Println("Error creating users table:", err) }

    createMessagesTable := `
    CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        sender TEXT NOT NULL,
        receiver TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`
    _, err = db.Exec(createMessagesTable)
    if err != nil { log.Println("Error creating messages table:", err) }
    // -----------------------------------------

    log.Println("Database connected & tables verified!")
}

func registerUser(c *gin.Context) {

    var input struct {
        Username string `json:"username"`
        Password string `json:"password"`
        Email    string `json:"email"`
    }

    if err := c.BindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    // Securely hash the password before saving to DB
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to secure password"})
        return
    }

    wingID := generateWingID()

    _, err = db.Exec(
        "INSERT INTO users (wing_id, username, password, email) VALUES ($1, $2, $3, $4)",
        wingID,
        input.Username,
        string(hashedPassword),
        input.Email,
    )

    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "username already exists",
        })
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "username": input.Username,
        "wing_id":  wingID,
    })
}

func loginUser(c *gin.Context) {

    var input struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }

    if err := c.BindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    var wingID string
    var storedHash string

    err := db.QueryRow(
        "SELECT wing_id, password FROM users WHERE username=$1",
        input.Username,
    ).Scan(&wingID, &storedHash)

    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{
            "error": "user not found",
        })
        return
    }

    // Compare the submitted password with the hashed password
    err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(input.Password))
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{
            "error": "invalid credentials",
        })
        return
    }

    token := generateWingID()

    sessionMutex.Lock()
    sessions[token] = wingID
    sessionMutex.Unlock()

    c.JSON(http.StatusOK, gin.H{
        "wing_id": wingID,
        "token":   token,
    })
}

func changePassword(c *gin.Context) {
    var input struct {
        WingID      string `json:"wing_id"`
        OldPassword string `json:"old_password"`
        NewPassword string `json:"new_password"`
    }

    if err := c.BindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    var storedHash string
    err := db.QueryRow("SELECT password FROM users WHERE wing_id=$1", input.WingID).Scan(&storedHash)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
        return
    }

    // Verify the old password is correct
    err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(input.OldPassword))
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "incorrect current password"})
        return
    }

    // Hash the new password and update the DB
    newHash, _ := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
    _, err = db.Exec("UPDATE users SET password=$1 WHERE wing_id=$2", string(newHash), input.WingID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update password"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "password updated successfully"})
}

func deleteAccount(c *gin.Context) {
    var input struct {
        WingID string `json:"wing_id"`
    }

    if err := c.BindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    // 1. Wipe their undelivered messages from the server
    db.Exec("DELETE FROM messages WHERE sender=$1 OR receiver=$1", input.WingID)
    
    // 2. Wipe their account data
    _, err := db.Exec("DELETE FROM users WHERE wing_id=$1", input.WingID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete account"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "account deleted successfully"})
}

func resetPassword(c *gin.Context) {
    var input struct {
        Username    string `json:"username"`
        Email       string `json:"email"`
        NewPassword string `json:"new_password"`
    }

    if err := c.BindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    var wingID string
    // Verify both username AND email match exactly
    err := db.QueryRow("SELECT wing_id FROM users WHERE username=$1 AND email=$2", input.Username, input.Email).Scan(&wingID)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "username and email do not match"})
        return
    }

    // Hash the newly provided password
    newHash, _ := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)

    // Update DB
    _, err = db.Exec("UPDATE users SET password=$1 WHERE wing_id=$2", string(newHash), wingID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reset password"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "password reset successfully"})
}

func uploadPublicKey(c *gin.Context) {

    var input struct {
        WingID    string `json:"wing_id"`
        PublicKey string `json:"public_key"`
    }

    if err := c.BindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "invalid request",
        })
        return
    }

    _, err := db.Exec(
        "UPDATE users SET public_key=$1 WHERE wing_id=$2",
        input.PublicKey,
        input.WingID,
    )

    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{
            "error": "database update failed",
        })
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "message": "public key stored",
    })
}

func uploadAvatar(c *gin.Context) {
    var input struct {
        WingID string `json:"wing_id"`
        Avatar string `json:"avatar"`
    }

    if err := c.BindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    _, err := db.Exec(
        "UPDATE users SET avatar=$1 WHERE wing_id=$2",
        input.Avatar,
        input.WingID,
    )

    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "database update failed"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "avatar stored successfully"})
}

func getPublicKey(c *gin.Context) {

    wingID := c.Param("wingid")

    var publicKey sql.NullString
    var username sql.NullString 
    var avatar sql.NullString 

    err := db.QueryRow(
        "SELECT username, public_key, avatar FROM users WHERE wing_id=$1",
        wingID,
    ).Scan(&username, &publicKey, &avatar)

    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{
            "error": "user not found",
        })
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "wing_id":    wingID,
        "username":   username.String,
        "public_key": publicKey.String,
        "avatar":     avatar.String, 
    })
}

func storeOfflineMessage(sender, receiver, ciphertext string) {

    _, err := db.Exec(
        "INSERT INTO messages (sender, receiver, ciphertext) VALUES ($1,$2,$3)",
        sender, receiver, ciphertext,
    )

    if err != nil {
        log.Println("DATABASE ERROR:", err)
    } else {
        log.Println("Message stored successfully")
    }
}

func deliverOfflineMessages(wingID string, conn *websocket.Conn) {

    rows, err := db.Query(
        "SELECT sender, ciphertext FROM messages WHERE receiver=$1",
        wingID,
    )

    if err != nil {
        return
    }

    defer rows.Close()

    for rows.Next() {

        var sender string
        var ciphertext string

        rows.Scan(&sender, &ciphertext)

        msg := Message{
            From:    sender,
            To:      wingID,
            Message: ciphertext,
        }

        conn.WriteJSON(msg)
    }

    db.Exec("DELETE FROM messages WHERE receiver=$1", wingID)
}

func handleSocket(c *gin.Context) {

    log.Println("WS REQUEST HIT")

    wingID := c.Query("wing_id")
    token := c.Query("token")

    sessionMutex.Lock()
    validWingID, ok := sessions[token]
    sessionMutex.Unlock()

    if !ok || validWingID != wingID {
        log.Println("INVALID TOKEN - allowing for debug:", wingID)
        // TEMP: allow connection
    }

    conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
    if err != nil {
        log.Println("UPGRADE ERROR:", err)
        return
    }

    log.Println("WS CONNECTED:", wingID)

    clientsMutex.Lock()
    clients[wingID] = conn
    clientsMutex.Unlock()

    deliverOfflineMessages(wingID, conn)

    for {

        var msg Message

        err := conn.ReadJSON(&msg)
        if err != nil {

            log.Println("READ ERROR:", err)

            clientsMutex.Lock()
            delete(clients, wingID)
            clientsMutex.Unlock()

            conn.Close()
            break
        }

        log.Println("MESSAGE RECEIVED:", msg)

        clientsMutex.Lock()
        receiver, ok := clients[msg.To]
        clientsMutex.Unlock()

        if ok {
            receiver.WriteJSON(msg)
        } else {
            storeOfflineMessage(msg.From, msg.To, msg.Message)
        }
    }
}

func main() {

    connectDB()

    router := gin.Default()

    router.GET("/health", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
            "status": "Wings Connect server running",
        })
    })

    router.GET("/ws", handleSocket)
    router.POST("/register", registerUser)
    router.POST("/login", loginUser)
    router.POST("/upload-key", uploadPublicKey)
    router.POST("/upload-avatar", uploadAvatar) 
    router.POST("/change-password", changePassword) 
    router.POST("/reset-password", resetPassword)
    router.POST("/delete-account", deleteAccount)   
    router.GET("/public-key/:wingid", getPublicKey)

    // --- 🟢 CLOUD PORT FIX 🟢 ---
    // Grabs the port assigned by Render, defaults to 8080 locally
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }

    log.Println("🚀 Connect by Wings backend starting on port " + port + "...")
    router.Run("0.0.0.0:" + port)
}