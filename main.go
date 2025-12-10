package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/mucusscraper/chirpy/internal/auth"
	"github.com/mucusscraper/chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits   atomic.Int32
	database_queries *database.Queries
	secret           string
}
type chirp struct {
	Body    string    `json:"body"`
	User_ID uuid.UUID `json:"user_id"`
}
type error_phrase struct {
	Error string `json:"error"`
}
type ReturningChirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

var secret_to_token string

func main() {
	godotenv.Load()
	db_URL := os.Getenv("DB_URL")
	secret_to_token = os.Getenv("SECRET")
	db, err := sql.Open("postgres", db_URL)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		return
	}
	dbQueries := database.New(db)
	apiCfg := &apiConfig{
		database_queries: dbQueries,
		secret:           secret_to_token,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", handler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.handler_number_requests)
	mux.HandleFunc("POST /admin/reset", apiCfg.handler_reset_counter)
	mux.HandleFunc("POST /api/users", apiCfg.handler_create_user)
	mux.HandleFunc("GET /api/chirps", apiCfg.handler_get_chirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handler_get_chirp)
	mux.HandleFunc("POST /api/chirps", apiCfg.handler_create_chirp)
	mux.HandleFunc("POST /api/login", apiCfg.handler_login)
	root := http.Dir(".")
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(root))))
	new_server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	new_server.ListenAndServe()
}

func handler(response http.ResponseWriter, request *http.Request) {
	header := response.Header()
	header.Set("Content-Type", "text/plain; charset=utf-8")
	response.WriteHeader(200)
	byte_message := []byte("OK")
	response.Write(byte_message)
}

func (cfg *apiConfig) handler_login(response http.ResponseWriter, request *http.Request) {
	type auth_info struct {
		Password         string `json:"password"`
		Email            string `json:"email"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
	}
	decoder := json.NewDecoder(request.Body)
	params := auth_info{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		return
	}
	user, err := cfg.database_queries.GetUserByEmail(request.Context(), params.Email)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		response.WriteHeader(401)
		return
	}
	valid, err := auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		response.WriteHeader(401)
		return
	}
	if !valid {
		response.WriteHeader(401)
		return
	} else {
		var expires time.Duration
		if params.ExpiresInSeconds > 3600 || params.ExpiresInSeconds == 0 {
			expires = 3600 * time.Second
		} else {
			expires = time.Duration(params.ExpiresInSeconds) * time.Second
		}
		token, err := auth.MakeJWT(user.ID, cfg.secret, expires)
		if err != nil {
			log.Printf("Error creating token: %s", err)
			return
		}
		type user_response struct {
			ID        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Email     string    `json:"email"`
			Token     string    `json:"token"`
		}
		new_response := &user_response{
			ID:        user.ID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
			Email:     user.Email,
			Token:     token,
		}
		data, err := json.Marshal(new_response)
		if err != nil {
			log.Printf("Unknown error")
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(200)
		response.Write(data)
	}
}

func (cfg *apiConfig) handler_get_chirp(response http.ResponseWriter, request *http.Request) {
	chirp_parse_id, err := uuid.Parse(request.PathValue("chirpID"))
	if err != nil {
		log.Printf("Error transforming string to uuid: %s", err)
		response.WriteHeader(400)
		return
	}
	chirp, err := cfg.database_queries.GetChirp(request.Context(), chirp_parse_id)
	if err != nil {
		log.Printf("Error finding the chirp: %s", err)
		response.WriteHeader(404)
		return
	}
	returning_chirp := ReturningChirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	}
	data_chirp, err := json.Marshal(returning_chirp)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(200)
	response.Write(data_chirp)
}

func (cfg *apiConfig) handler_get_chirps(response http.ResponseWriter, request *http.Request) {
	all_chirps, err := cfg.database_queries.GetChirps(request.Context())
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		return
	}
	var list_of_chirps []ReturningChirp
	for _, value := range all_chirps {
		chirp_to_be_appended := ReturningChirp{
			ID:        value.ID,
			CreatedAt: value.CreatedAt,
			UpdatedAt: value.UpdatedAt,
			Body:      value.Body,
			UserID:    value.UserID,
		}
		list_of_chirps = append(list_of_chirps, chirp_to_be_appended)
	}
	data_list_of_chirps, err := json.Marshal(list_of_chirps)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(200)
	response.Write(data_list_of_chirps)
}

func (cfg *apiConfig) handler_create_chirp(response http.ResponseWriter, request *http.Request) {
	decoder := json.NewDecoder(request.Body)
	params := chirp{}
	list_of_profane := []string{"kerfuffle", "sharbert", "fornax"}
	err := decoder.Decode(&params)
	if err != nil {
		resp_body := error_phrase{
			Error: "Something went wrong",
		}
		data, err := json.Marshal(resp_body)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			return
		}
		response.WriteHeader(500)
		response.Header().Set("Content-Type", "application/json")
		response.Write(data)
		log.Printf("Error decoding parameters: %s", err)
		return
	}
	if len(params.Body) > 140 {
		resp_body := error_phrase{
			Error: "Chirp is too long",
		}
		data, err := json.Marshal(resp_body)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			return
		}
		response.WriteHeader(400)
		response.Header().Set("Content-Type", "application/json")
		response.Write(data)
		return
	} else {
		new_string := []string{}
		for _, word := range strings.Split(params.Body, " ") {
			is_profane := false
			for _, profane_word := range list_of_profane {
				if strings.ToLower(word) == profane_word {
					is_profane = true
					break
				}
			}
			if is_profane {
				new_string = append(new_string, "****")
			} else {
				new_string = append(new_string, word)
			}
		}
		returning_string := strings.Join(new_string, " ")
		token, err := auth.GetBearerToken(request.Header)
		if err != nil {
			log.Printf("Error bearing token: %s", err)
			response.WriteHeader(401)
			return
		}
		id_to_test, err := auth.ValidateJWT(token, cfg.secret)
		if err != nil {
			log.Printf("Error validating JWT: %s", err)
			response.WriteHeader(401)
			return
		}
		chirp_model := database.CreateChirpParams{
			Body:   returning_string,
			UserID: id_to_test,
		}
		database_chirp, err := cfg.database_queries.CreateChirp(request.Context(), chirp_model)
		if err != nil {
			log.Printf("Error creating user in database: %s", err)
			return
		}
		created_chirp := &ReturningChirp{
			ID:        database_chirp.ID,
			CreatedAt: database_chirp.CreatedAt,
			UpdatedAt: database_chirp.UpdatedAt,
			Body:      database_chirp.Body,
			UserID:    id_to_test,
		}
		data_created_chirp, err := json.Marshal(created_chirp)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(201)
		response.Write(data_created_chirp)
	}
}

func (cfg *apiConfig) handler_create_user(response http.ResponseWriter, request *http.Request) {
	type email_input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	type User struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
		Password  string    `json:"-"`
	}
	decoder := json.NewDecoder(request.Body)
	params := email_input{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		return
	}
	hash_password, err := auth.HashPassword(params.Password)
	if err != nil {
		return
	}
	user_params := database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hash_password,
	}
	database_user, err := cfg.database_queries.CreateUser(request.Context(), user_params)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		return
	}
	created_user := &User{
		ID:        database_user.ID,
		CreatedAt: database_user.CreatedAt,
		UpdatedAt: database_user.UpdatedAt,
		Email:     database_user.Email,
		Password:  hash_password,
	}
	data_created_user, err := json.Marshal(created_user)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(201)
	response.Write(data_created_user)
}

func (cfg *apiConfig) handler_reset_counter(response http.ResponseWriter, request *http.Request) {
	platform := os.Getenv("PLATFORM")
	if platform != "dev" {
		response.WriteHeader(403)
		return
	}
	err := cfg.database_queries.DeleteUsers(request.Context())
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		return
	}
	header := response.Header()
	header.Set("Content-Type", "text/plain; charset=utf-8")
	response.WriteHeader(200)
	cfg.fileserverHits.Swap(0)
}

func (cfg *apiConfig) handler_number_requests(response http.ResponseWriter, request *http.Request) {
	header := response.Header()
	header.Set("Content-Type", "text/html")
	response.WriteHeader(200)
	phrase := fmt.Sprintf(
		`<html>
  		<body>
    		<h1>Welcome, Chirpy Admin</h1>
    		<p>Chirpy has been visited %d times!</p>
  		</body>
	</html>`,
		cfg.fileserverHits.Load())
	byte_message := []byte(phrase)
	response.Write(byte_message)
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}
