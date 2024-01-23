package routes

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"project_login/database"
	"project_login/helpers"
	"project_login/models"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var Store = sessions.NewCookieStore([]byte("secret"))

type Users struct {
	ID       int
	Username string
	Password string
}

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Fatal(err)
	}
	return string(bytes)
}

func VerifyPassword(userPassword string, providedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	if err != nil {
		check = false
	}
	return check

}

func Login(c *gin.Context) {
	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	ok, _ := UserLoged(c)
	if ok {
		c.Redirect(303, "/home")
		return
	}
	c.HTML(http.StatusOK, "login.html", nil)
}

func PostLogin(c *gin.Context) {
	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	// var _, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	var user Users
	username := c.Request.FormValue("username")
	password := c.Request.FormValue("password")

	db := database.InitDB()
	db.Where("username=?", username).First(&user)
	passwordIsValid := VerifyPassword(password, user.Password)

	if username == user.Username && passwordIsValid {
		token, _, _ := helpers.GenerateTokens(username, "User")
		session, _ := Store.Get(c.Request, "jwt_token")
		session.Values["token"] = token
		session.Values["user"] = username
		session.Save(c.Request, c.Writer)
		// defer Close()
		c.Redirect(http.StatusSeeOther, "/home")
		// c.HTML(200, "welcomeuser.html", gin.H{
		// 	"message": username,
		// })
		return
	}

	c.HTML(303, "login.html", gin.H{
		"error": "invalid username or password",
	})

}

func Signup(c *gin.Context) {
	c.HTML(http.StatusOK, "signup.html", nil)
}

func PostSignup(c *gin.Context) {
	var user Users
	username := c.Request.FormValue("username")
	password := HashPassword(c.Request.FormValue("password"))

	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)

	if username == "" {
		c.HTML(303, "signup.html", gin.H{
			"message": "empty username or password try again",
		})
		return
	}
	if password == "" {
		c.HTML(303, "signup.html", gin.H{
			"message": "empty username or password try again",
		})
		return
	}

	db := database.InitDB()
	db.AutoMigrate(&Users{})
	db.Where("username=?", username).First(&user)

	if user.Username == username {
		c.HTML(303, "signup.html", gin.H{
			"message": "This username is already taken",
		})
		return
	}

	// if !status {
	// 	log.Printf("hello %s , The username is already taken", FusernameN)
	// 	c.Redirect(303, "/signup")
	// 	return

	// }

	db.Create(&Users{Username: username, Password: password})
	log.Printf("Hey %s, Your account is successfully created.", username)
	// c.Redirect(http.StatusSeeOther, "/login")
	c.HTML(202, "login.html", gin.H{
		"success": "successfully created " + username,
	})

}

func Admin(c *gin.Context) {
	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	ok := AdminLoged(c)
	if ok {
		c.Redirect(303, "/wadmin")
		return
	}
	c.HTML(http.StatusOK, "admin.html", nil)
}

func PostAdmin(c *gin.Context) {

	config := &models.Admin{
		UserName: os.Getenv("ADMIN_NAME"),
		Password: os.Getenv("PASSWORD"),
	}

	// config.Password = HashPassword(config.Password)

	username := c.Request.FormValue("username")
	password := c.Request.FormValue("password")

	// passwordIsValid := VerifyPassword(password, config.Password)

	if username != config.UserName || config.Password != password {
		log.Println("Wrong Username or Password , Check Again!")
		c.Redirect(303, "/admin")
		return
	}

	token, _, _ := helpers.GenerateTokens(username, "Admin")

	session, _ := Store.Get(c.Request, "admin_jwt_token")
	session.Values["token"] = token
	session.Save(c.Request, c.Writer)
	// c.Redirect(http.StatusSeeOther, "/home")

	c.Redirect(303, "/wadmin")

}

func Wadmin(c *gin.Context) {
	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	var user []Users

	ok := AdminLoged(c)
	if !ok {
		c.Redirect(303, "/admin")
		return
	}

	db := database.InitDB()
	var us = [11]string{}

	var id = [11]int{}
	db.Raw("SELECT id,username FROM users").Scan(&user)
	for ind, i := range user {
		us[ind+1], id[ind+1] = i.Username, i.ID

	}

	c.HTML(http.StatusOK, "welcomeadmin.html", gin.H{

		"users": us,
		"id":    id,
	})
}

func Home(c *gin.Context) {
	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	ok, user := UserLoged(c)
	if !ok {
		c.Redirect(303, "/login")
		return
	}
	c.HTML(http.StatusSeeOther, "welcomeuser.html", gin.H{
		"message": user,
	})                        
	// c.Redirect(http.StatusSeeOther, "/home")
}

func Logout(c *gin.Context) {

	cookie, err := c.Request.Cookie("jwt_token")
	if err != nil {
		c.Redirect(303, "/login")
	}
	c.SetCookie("jwt_token", "", -1, "/", "localhost", false, true)
	_ = cookie
	c.Redirect(http.StatusSeeOther, "/login")
}

func DeleteUser(c *gin.Context) {
	var user Users
	name := c.Param("name")
	db := database.InitDB()
	db.Where("username=?", name).Delete(&user)
	c.Redirect(303, "/wadmin")

}

func UpdateUser(c *gin.Context) {

	updateData := c.Request.FormValue("updatedata")
	var user Users
	name := c.Param("name")
	db := database.InitDB()
	db.Model(&user).Where("username=?", name).Update("username", updateData)
	c.Redirect(303, "/wadmin")
}

func CreateUser(c *gin.Context) {
	var user Users

	username := c.Request.FormValue("username")
	password := HashPassword(c.Request.FormValue("password"))

	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)

	if username == "" || password == "" {
		c.Redirect(303, "/wadmin")
		return
	}

	//database things
	db := database.InitDB()
	db.AutoMigrate(&Users{})
	db.Where("username=?", username).First(&user)

	if user.Username == username {
		log.Println("hello Admin , The username is already in Use")
		c.Redirect(303, "/wadmin")
		return

	}

	db.Create(&Users{Username: username, Password: password})
	log.Println("Hey Admin, Account is successfully created.")
	c.Redirect(http.StatusSeeOther, "/wadmin")

}

func IndexHandler(c *gin.Context) {
	session, _ := Store.Get(c.Request, "jwt_token")
	_, ok := session.Values["token"]
	if !ok {
		c.Redirect(303, "/login")
		return
	}
	c.Redirect(303, "/home")
}

func AdminLoged(c *gin.Context) bool {
	session, _ := Store.Get(c.Request, "admin_jwt_token")
	token, ok := session.Values["token"]
	fmt.Println(token)
	if !ok {
		return ok
	}
	return true
}

func UserLoged(c *gin.Context) (bool, interface{}) {

	session, _ := Store.Get(c.Request, "jwt_token")
	token, ok := session.Values["token"]
	user := session.Values["user"]
	fmt.Println(token)
	if !ok {

		return ok, nil
	}
	return true, user

}

func LogoutAdmin(c *gin.Context) {

	cookie, err := c.Request.Cookie("admin_jwt_token")
	if err != nil {
		c.Redirect(303, "/admin")
	}
	c.SetCookie("admin_jwt_token", "", -1, "/", "localhost", false, false)
	_ = cookie
	c.Redirect(http.StatusSeeOther, "/admin")
}
