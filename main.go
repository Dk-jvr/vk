package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-playground/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	db        *sql.DB
	dbMutex   sync.Mutex
	secretKey *ecdsa.PrivateKey
)

type (
	User struct {
		Username string `json:"username" validate:"required"`
		Password string `json:"password" validate:"required"`
	}

	Actor struct {
		Name        string `json:"name" validate:"required"`
		ActorGender string `json:"actorGender" validate:"required"`
		BirthDay    string `json:"birthDay" validate:"required"`
	}

	ActorList struct {
		Name        string   `json:"name"`
		ActorGender string   `json:"actorGender"`
		BirthDay    string   `json:"birthDay"`
		Films       []string `json:"films"`
	}

	Film struct {
		Name        string  `json:"name" validate:"required,min=1,max=150"`
		Description string  `json:"description" validate:"required,max=1000"`
		ReleaseDate string  `json:"releaseDate" validate:"required"`
		Rating      int     `json:"rating" validate:"required,max=10"`
		CastList    []Actor `json:"castList" validate:"required"`
	}

	FilmList struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		ReleaseDate string   `json:"releaseDate"`
		Rating      int      `json:"rating"`
		CastList    []string `json:"castList"`
	}
)

func InitDataBase() *sql.DB {
	var err error
	connectionString := "user=user dbname=filmLibrary password=password host=localhost port=5432 sslmode=disable"
	secretKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	db, err = sql.Open("postgres", connectionString)
	if err != nil {
		fmt.Printf("Connection to database error: %s", err.Error())
		return nil
	}
	const queryTables = `
			DROP TABLE IF EXISTS Users;
			DROP TABLE IF EXISTS Actors CASCADE;
			DROP TABLE IF EXISTS Films CASCADE;
			DROP TABLE IF EXISTS ActorsAndFilms;

			CREATE TABLE IF NOT EXISTS Users (
			    user_id UUID PRIMARY KEY,
			    username TEXT UNIQUE NOT NULL,
			    role TEXT NOT NULL,
			    password BYTEA NOT NULL
			);

			INSERT INTO Users VALUES ('3d821044-6dca-4dea-8b25-69e118ac6152'::uuid, 'admin', 'admin',
			    '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'::bytea), /*password : admin*/
			                      ('3841d1b2-7f71-4323-a8fe-c70a3c435a84'::uuid, 'user', 'user',
			    '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'::bytea); /*password : password*/
			
			CREATE TABLE IF NOT EXISTS Actors (
			    actor_id UUID PRIMARY KEY,
			    actor_name TEXT NOT NULL,
			    birthDay DATE NOT NULL,
			    gender TEXT
			);
			CREATE TABLE IF NOT EXISTS Films (
			    film_id UUID PRIMARY KEY,
			    film_name TEXT NOT NULL,
			    description TEXT,
			    release_date DATE NOT NULL,
			    rating INTEGER
			);
			CREATE TABLE IF NOT EXISTS ActorsAndFilms (
			    actor_id UUID,
			    film_id UUID,
			    PRIMARY KEY(actor_id, film_id),
			    CONSTRAINT FK_actor FOREIGN KEY(actor_id)
			        REFERENCES Actors(actor_id),
			    CONSTRAINT FK_film FOREIGN KEY(film_id)
			        REFERENCES Films(film_id)
			)
		`
	dbMutex.Lock()
	defer dbMutex.Unlock()
	_, err = db.Exec(queryTables)
	if err != nil {
		log.Fatal(err.Error())
		return nil
	}
	log.Println("Initialization Database Successful")
	return db
}

func HashPassword(password string) string {
	hash := sha256.New()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}

func CreateToken(userRole string) (string, error) {
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Subject:   userRole,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tokenStr, err := token.SignedString(secretKey)
	return tokenStr, err
}

func SetCookie(writer http.ResponseWriter, tokenStr string) {
	cookie := &http.Cookie{
		Name:     "jwt",
		Value:    tokenStr,
		Expires:  time.Now().Add(time.Hour * 1),
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(writer, cookie)
}

func TokenValidation(tokenStr string) error {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return &secretKey.PublicKey, nil
	})
	if err != nil {
		return err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid && time.Now().Unix() < int64(claims["exp"].(float64)) {
		return nil
	} else {
		return errors.New("Invalid Token Error")
	}
}

func Login(writer http.ResponseWriter, request *http.Request) {
	user := new(User)
	role := ""
	err := json.NewDecoder(request.Body).Decode(user)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
	}
	validate := validator.New()
	err = validate.Struct(user)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
	}
	sha256Password := HashPassword(user.Password)
	dbMutex.Lock()
	defer dbMutex.Unlock()
	err = db.QueryRow(`SELECT role FROM Users
									WHERE username = $1 AND password = $2`, user.Username, sha256Password).Scan(&role)
	if role != "" && err == nil {
		tokenStr, _ := CreateToken(role)
		SetCookie(writer, tokenStr)
		log.Println("Successful Authorization")
		return
	} else {
		log.Println("User Not Found")
		http.Error(writer, "User Not Found", http.StatusNotFound)
	}
	return
}

func AddActor(writer http.ResponseWriter, request *http.Request) {
	const queryInsertNewActor = `INSERT INTO Actors VALUES ($1, $2, $3, $4);`

	actor := new(Actor)

	err := json.NewDecoder(request.Body).Decode(actor)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	validate := validator.New()
	err = validate.Struct(actor)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		log.Fatal(err)
		return
	}
	actorId := uuid.New()
	var birthDate time.Time
	birthDate, err = time.Parse("2006-01-02", actor.BirthDay)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		log.Fatal(err)
		return
	}
	dbMutex.Lock()
	defer dbMutex.Unlock()
	_, err = db.Exec(queryInsertNewActor, actorId, actor.Name, birthDate, actor.ActorGender)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		log.Fatal(err)
	}
	log.Println("Actor added successfully")
	return
}

func AddFilm(writer http.ResponseWriter, request *http.Request) {
	const queryInsertNewFilm = `INSERT INTO Films VALUES ($1, $2, $3, $4, $5);`
	const queryInsertActorInFilm = `INSERT INTO ActorsAndFilms VALUES ((SELECT actor_id FROM Actors WHERE actor_name = $2), $1);`
	film := new(Film)
	err := json.NewDecoder(request.Body).Decode(film)
	if err != nil {
		http.Error(writer, "Bad Request", http.StatusBadRequest)
		log.Fatal(err)
		return
	}
	validate := validator.New()
	err = validate.Struct(film)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		log.Fatal(err)
		return
	}
	filmId := uuid.New()
	var releaseDate time.Time
	releaseDate, err = time.Parse("2006-01-02", film.ReleaseDate)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		log.Fatal(err)
		return
	}
	dbMutex.Lock()
	defer dbMutex.Unlock()
	_, err = db.Exec(queryInsertNewFilm, filmId, film.Name, film.Description, releaseDate, film.Rating)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		log.Fatal(err)
		return
	}
	for _, actor := range film.CastList {
		_, err = db.Exec(queryInsertActorInFilm, filmId, actor.Name)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			log.Fatal(err)
			return
		}
	}
	log.Println("Film added successfully")
	return
}

func Actors(writer http.ResponseWriter, request *http.Request) {
	var list []ActorList
	const query = `SELECT a.actor_name, a.birthDay, a.gender,
       ARRAY(SELECT f.film_name FROM ActorsAndFilms af 
             INNER JOIN Films f ON f.film_id = af.film_id
             WHERE af.actor_id = a.actor_id) AS films
FROM Actors a;`
	res, err := db.Query(query)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		log.Fatal(err)
		return
	}
	for res.Next() {
		var actor ActorList
		var films sql.NullString
		res.Scan(&actor.Name, &actor.BirthDay, &actor.ActorGender, &films)
		if films.Valid {
			actor.Films = strings.Split(films.String, ",")
		}
		list = append(list, actor)
	}
	json.NewEncoder(writer).Encode(list)
	log.Println("Get actor list")
	return
}

func Films(writer http.ResponseWriter, request *http.Request) {
	sortType := request.URL.Query().Get("sort")
	field := request.URL.Query().Get("field")
	var titleList []FilmList
	if sortType == "" {
		sortType = "DESC"
	}
	if field == "" {
		field = "rating"
	}
	query := fmt.Sprintf("SELECT f.film_name, f.description, f.rating, f.release_date, "+
		"ARRAY(SELECT a.actor_name FROM ActorsAndFilms af "+
		"INNER JOIN Actors a ON a.actor_id = af.actor_id "+
		"WHERE af.film_id = f.film_id) AS actors FROM Films f "+
		"ORDER BY %s %s;", field, sortType)

	rows, err := db.Query(query)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		log.Fatal(err)
		return
	}
	for rows.Next() {
		var film FilmList
		var actors sql.NullString
		rows.Scan(&film.Name, &film.Description, &film.Rating, &film.ReleaseDate, &actors)
		if actors.Valid {
			film.CastList = strings.Split(actors.String, ",")
		}
		titleList = append(titleList, film)
	}
	json.NewEncoder(writer).Encode(titleList)
	log.Println("Get film list")
	return
}

func ActorProcessing(writer http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	actor_name := vars["actor"]
	switch request.Method {
	case http.MethodDelete:
		const queryDeleteActor = `DELETE FROM Actors WHERE actor_name = $1`
		dbMutex.Lock()
		defer dbMutex.Unlock()
		_, err := db.Exec(`DELETE FROM ActorsAndFilms
					WHERE actor_id = (SELECT actor_id FROM Actors WHERE actor_name = $1)`, actor_name)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			log.Fatal(err)
			return
		}
		_, err = db.Exec(queryDeleteActor, actor_name)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			log.Fatal(err)
			return
		}
		log.Println("Successful actor delete")
		return
	case http.MethodPost:
		actor := new(Actor)
		err := json.NewDecoder(request.Body).Decode(actor)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			log.Fatal(err)
			return
		}
		dbMutex.Lock()
		defer dbMutex.Unlock()
		if actor.ActorGender != "" {
			_, err = db.Exec(`UPDATE Actors
								SET gender = $1 WHERE actor_name = $2`, actor.ActorGender, actor_name)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				log.Fatal(err)
				return
			}
		}
		if actor.BirthDay != "" {
			bDay, parseErr := time.Parse("2006-01-02", actor.BirthDay)
			if parseErr != nil {
				http.Error(writer, parseErr.Error(), http.StatusBadRequest)
				log.Fatal(err)
				return
			}
			_, err = db.Exec(`UPDATE Actors
								SET birthDay = $1 WHERE actor_name = $2`, bDay, actor_name)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				log.Fatal(err)
				return
			}
		}
		if actor.Name != "" {
			_, err = db.Exec(`UPDATE Actors
								SET actor_name = $1 WHERE actor_name = $2`, actor.Name, actor_name)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				log.Fatal(err)
				return
			}
		}
		log.Println("Successful actor update")
		return

	default:
		http.Error(writer, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func FilmProcessing(writer http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	film_name := vars["film"]
	switch request.Method {
	case http.MethodDelete:
		const queryDeleteActor = `DELETE FROM Actors WHERE film_name = $1`
		dbMutex.Lock()
		defer dbMutex.Unlock()
		_, err := db.Exec(`DELETE FROM ActorsAndFilms
					WHERE film_id = (SELECT film_id FROM Films WHERE film_name = $1)`, film_name)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			log.Fatal(err)
			return
		}
		_, err = db.Exec(queryDeleteActor, film_name)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			log.Fatal(err)
			return
		}
		log.Println("Successful film delete")
		return
	case http.MethodPost:
		film := new(Film)
		err := json.NewDecoder(request.Body).Decode(film)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			log.Fatal(err)
			return
		}
		dbMutex.Lock()
		defer dbMutex.Unlock()
		if len(film.CastList) != 0 {
			_, err = db.Exec(`DELETE FROM ActorsAndFilms 
       			WHERE film_id = (SELECT film_id FROM Films WHERE film_name = $1)`, film_name)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				log.Fatal(err)
				return
			}
			for _, value := range film.CastList {
				_, err = db.Exec(`INSERT INTO ActorsAndFilms VALUES ((SELECT actor_id FROM Actors WHERE actor_name = $2), (SELECT film_id FROM Films 
                                                   WHERE film_name = $1));`, film_name, value.Name)
				if err != nil {
					http.Error(writer, err.Error(), http.StatusInternalServerError)
					log.Fatal(err)
					return
				}
			}
		}
		if film.Rating != 0 {
			_, err = db.Exec(`UPDATE Films
					SET rating = $2 WHERE film_name = $1`, film_name, film.Rating)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				log.Fatal(err)
				return
			}
		}
		if film.ReleaseDate != "" {
			releaseDate, parseErr := time.Parse("2006-01-02", film.ReleaseDate)
			if parseErr != nil {
				http.Error(writer, parseErr.Error(), http.StatusBadRequest)
				log.Fatal(err)
				return
			}
			_, err = db.Exec(`UPDATE Films
					SET release_date = $2 WHERE film_name = $1`, film_name, releaseDate)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				log.Fatal(err)
				return
			}
		}
		if film.Description != "" {
			_, err = db.Exec(`UPDATE Films
					SET description = $2 WHERE film_name = $1`, film_name, film.Description)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				log.Fatal(err)
				return
			}
		}
		if film.Name != "" {
			_, err = db.Exec(`UPDATE Films
					SET film_name = $2 WHERE film_name = $1`, film_name, film.Name)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				log.Fatal(err)
				return
			}
		}
		log.Println("Successful film update")
		return
	default:
		http.Error(writer, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func SearchFilm(writer http.ResponseWriter, request *http.Request) {
	titlePart := request.URL.Query().Get("title")
	actorPart := request.URL.Query().Get("actor")
	var title string

	dbMutex.Lock()
	defer dbMutex.Unlock()
	if actorPart != "" && titlePart != "" {
		titlePart = "%" + titlePart + "%"
		actorPart = "%" + actorPart + "%"
		const queryString = `SELECT f.film_name FROM ActorsAndFilms af
							INNER JOIN Films f ON f.film_id = af.film_id
							INNER JOIN Actors a ON a.actor_id = af.actor_id
							WHERE f.film_name LIKE $1 AND a.actor_name LIKE $2`
		db.QueryRow(queryString, titlePart, actorPart).Scan(&title)
		writer.Write([]byte(title))
		return
	}
	if titlePart != "" {
		titlePart = "%" + titlePart + "%"
		const queryString = `SELECT f.film_name FROM ActorsAndFilms af
							INNER JOIN Films f ON f.film_id = af.film_id
							WHERE f.film_name LIKE $1`
		db.QueryRow(queryString, titlePart).Scan(&title)
		writer.Write([]byte(title))
		return
	}
	if actorPart != "" {
		actorPart = "%" + actorPart + "%"
		const queryString = `SELECT f.film_name FROM ActorsAndFilms af
							INNER JOIN Films f ON f.film_id = af.film_id
							INNER JOIN Actors a ON a.actor_id = af.actor_id
							WHERE a.actor_name LIKE $1`
		db.QueryRow(queryString, titlePart, actorPart).Scan(&title)
		writer.Write([]byte(title))
		return
	}
	log.Println("Successful search film")
	return
}

func adminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie("jwt")
		token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			return &secretKey.PublicKey, nil
		})
		if err != nil {
			http.Error(writer, "Access Denied", http.StatusForbidden)
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if role, _ := claims.GetSubject(); role == "admin" && ok {
			next.ServeHTTP(writer, request)
		} else {
			http.Error(writer, "Access Denied", http.StatusForbidden)
			return
		}
	})
}

func userAuthMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/login" {
			next.ServeHTTP(writer, request)
			return
		}

		cookie, err := request.Cookie("jwt")
		if err != nil {
			http.Error(writer, "Access Denied", http.StatusForbidden)
			return
		}
		err = TokenValidation(cookie.Value)
		if err != nil {
			http.Error(writer, "Access Denied", http.StatusForbidden)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func main() {
	database := InitDataBase()
	defer database.Close()

	adminMux := mux.NewRouter()
	adminMux.HandleFunc("/admin/film", AddFilm)
	adminMux.HandleFunc("/admin/actor", AddActor)
	adminMux.HandleFunc("/admin/actors/{actor}", ActorProcessing)
	adminMux.HandleFunc("/admin/films/{film}", FilmProcessing)

	adminHandler := adminAuthMiddleware(adminMux)

	siteMux := mux.NewRouter()
	siteMux.PathPrefix("/admin").Handler(adminHandler)
	siteMux.HandleFunc("/actors", Actors)
	siteMux.HandleFunc("/films", Films)
	siteMux.HandleFunc("/film", SearchFilm)
	siteMux.HandleFunc("/login", Login)

	siteHandler := userAuthMiddleWare(siteMux)

	log.Fatal(http.ListenAndServe("localhost:3000", siteHandler))

	//)
}
