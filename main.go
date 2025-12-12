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
	polkakey         string
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
	polka_key := os.Getenv("POLKA_KEY")
	db, err := sql.Open("postgres", db_URL)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		return
	}
	dbQueries := database.New(db)
	apiCfg := &apiConfig{
		database_queries: dbQueries,
		secret:           secret_to_token,
		polkakey:         polka_key,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", handler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.handler_number_requests)
	mux.HandleFunc("POST /admin/reset", apiCfg.handler_reset_counter)
	mux.HandleFunc("POST /api/users", apiCfg.handler_create_user)
	mux.HandleFunc("PUT /api/users", apiCfg.handler_update_user)
	mux.HandleFunc("GET /api/chirps", apiCfg.handler_get_chirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handler_get_chirp)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.handler_delete_chirp)
	mux.HandleFunc("POST /api/chirps", apiCfg.handler_create_chirp)
	mux.HandleFunc("POST /api/login", apiCfg.handler_login)
	mux.HandleFunc("POST /api/refresh", apiCfg.handler_refresh)
	mux.HandleFunc("POST /api/revoke", apiCfg.handler_revoke)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.handler_update_to_red)
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

func (cfg *apiConfig) handler_update_user(response http.ResponseWriter, request *http.Request) {
	token, err := auth.GetBearerToken(request.Header)
	if err != nil {
		log.Printf("Error getting access token: %s", err)
		response.WriteHeader(401)
		return
	} else {
		type get_user_data struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		decoder := json.NewDecoder(request.Body)
		params := get_user_data{}
		err = decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			response.WriteHeader(401)
			return
		}
		new_email := params.Email
		pass_pre_hash := params.Password
		pass_post_hash, err := auth.HashPassword(pass_pre_hash)
		if err != nil {
			log.Printf("Error hashing password: %s", err)
			response.WriteHeader(401)
			return
		}
		id_to_test, err := auth.ValidateJWT(token, cfg.secret)
		if err != nil {
			log.Printf("Error validating token: %s", err)
			response.WriteHeader(401)
			return
		}
		user_update_params := database.UpdateUserParams{
			Email:          new_email,
			HashedPassword: pass_post_hash,
			ID:             id_to_test,
		}
		err = cfg.database_queries.UpdateUser(request.Context(), user_update_params)
		if err != nil {
			log.Printf("Error updating user: %s", err)
			response.WriteHeader(401)
			return
		}
		type new_response_struct struct {
			ID          uuid.UUID `json:"id"`
			CreatedAt   time.Time `json:"created_at"`
			UpdatedAt   time.Time `json:"updated_at"`
			Email       string    `json:"email"`
			IsChirpyRed bool      `json:"is_chirpy_red"`
		}
		data_user, err := cfg.database_queries.GetUserByEmail(request.Context(), new_email)
		if err != nil {
			response.WriteHeader(401)
			return
		}
		new_response := &new_response_struct{
			ID:          id_to_test,
			CreatedAt:   data_user.CreatedAt,
			UpdatedAt:   data_user.UpdatedAt,
			Email:       new_email,
			IsChirpyRed: data_user.IsChirpyRed.Bool,
		}
		response_data, err := json.Marshal(new_response)
		if err != nil {
			log.Printf("Error hashing password: %s", err)
			response.WriteHeader(401)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(200)
		response.Write(response_data)
	}
}

func (cfg *apiConfig) handler_update_to_red(response http.ResponseWriter, request *http.Request) {
	key, err := auth.GetAPIKey(request.Header)
	if err != nil {
		log.Printf("Key not found")
		response.WriteHeader(401)
		return
	}
	if key != cfg.polkakey {
		response.WriteHeader(401)
		return
	}
	type data_data_struct struct {
		User_ID uuid.UUID `json:"user_id"`
	}
	type data_to_red_struct struct {
		Event string           `json:"event"`
		Data  data_data_struct `json:"data"`
	}
	decoder := json.NewDecoder(request.Body)
	params := data_to_red_struct{}
	err = decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		response.WriteHeader(401)
		return
	}
	if params.Event != "user.upgraded" {
		response.WriteHeader(204)
		return
	} else {
		err = cfg.database_queries.UpdateUserToRed(request.Context(), params.Data.User_ID)
		if err != nil {
			log.Printf("User not found: %s", err)
			response.WriteHeader(404)
		} else {
			response.WriteHeader(204)
		}
	}
}

func (cfg *apiConfig) handler_login(response http.ResponseWriter, request *http.Request) {
	type auth_info struct {
		Password string `json:"password"`
		Email    string `json:"email"`
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
		refresh_token, err := auth.MakeRefreshToken()
		if err != nil {
			log.Printf("Error making refresh token")
			return
		}
		token, err := auth.MakeJWT(user.ID, cfg.secret)
		if err != nil {
			log.Printf("Error creating token: %s", err)
			return
		}
		type user_response struct {
			ID           uuid.UUID `json:"id"`
			CreatedAt    time.Time `json:"created_at"`
			UpdatedAt    time.Time `json:"updated_at"`
			Email        string    `json:"email"`
			Token        string    `json:"token"`
			RefreshToken string    `json:"refresh_token"`
			IsChirpyRed  bool      `json:"is_chirpy_red"`
		}
		new_response := &user_response{
			ID:           user.ID,
			CreatedAt:    user.CreatedAt,
			UpdatedAt:    user.UpdatedAt,
			Email:        user.Email,
			Token:        token,
			RefreshToken: refresh_token,
			IsChirpyRed:  user.IsChirpyRed.Bool,
		}
		data, err := json.Marshal(new_response)
		if err != nil {
			log.Printf("Unknown error")
			return
		}
		refresh_token_params := database.RefreshTokenParams{
			Token:     refresh_token,
			ExpiresAt: time.Now().Add(3600 * 24 * 60 * time.Second),
			UserID:    user.ID,
		}
		_, err = cfg.database_queries.RefreshToken(request.Context(), refresh_token_params)
		if err != nil {
			log.Printf("Unknown error creating refresh token in database")
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(200)
		response.Write(data)
	}
}

func (cfg *apiConfig) handler_revoke(response http.ResponseWriter, request *http.Request) {
	authHeader := request.Header.Get("Authorization")
	if authHeader == "" {
		log.Printf("missing authorization header")
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 {
		log.Printf("malformed authorization header")
		return
	}

	scheme := strings.ToLower(parts[0])
	if scheme != "bearer" {
		log.Printf("expected bearer scheme")
		return
	}
	refresh_token_to_search := parts[1]
	err := cfg.database_queries.RevokeToken(request.Context(), refresh_token_to_search)
	if err != nil {
		log.Printf("Error revoking token")
	}
	response.WriteHeader(204)
}

func (cfg *apiConfig) handler_refresh(response http.ResponseWriter, request *http.Request) {
	authHeader := request.Header.Get("Authorization")
	if authHeader == "" {
		log.Printf("missing authorization header")
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 {
		log.Printf("malformed authorization header")
		return
	}

	scheme := strings.ToLower(parts[0])
	if scheme != "bearer" {
		log.Printf("expected bearer scheme")
		return
	}
	refresh_token_to_search := parts[1]
	refresh_token, err := cfg.database_queries.SearchRefreshToken(request.Context(), refresh_token_to_search)
	if err != nil || refresh_token.ExpiresAt.Before(time.Now()) || refresh_token.RevokedAt.Valid {
		log.Printf("Token not found")
		response.WriteHeader(401)
		return
	} else {
		user_id := refresh_token.UserID
		new_token, err := auth.MakeJWT(user_id, cfg.secret)
		if err != nil {
			log.Printf("Error creating new access token")
			return
		}
		type token_response struct {
			Token string `json:"token"`
		}
		token_response_pre_data := token_response{
			Token: new_token,
		}
		token_response_data, err := json.Marshal(token_response_pre_data)
		if err != nil {
			log.Printf("Error marshaling the token")
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(200)
		response.Write(token_response_data)
		return
	}
}

func (cfg *apiConfig) handler_delete_chirp(response http.ResponseWriter, request *http.Request) {
	chirp_parse_id, err := uuid.Parse(request.PathValue("chirpID"))
	if err != nil {
		log.Printf("Error transforming string to uuid: %s", err)
		response.WriteHeader(401)
		return
	}
	token, err := auth.GetBearerToken(request.Header)
	if err != nil {
		log.Printf("Error getting access token: %s", err)
		response.WriteHeader(401)
		return
	} else {
		id_to_test, err := auth.ValidateJWT(token, cfg.secret)
		if err != nil {
			log.Printf("Error validating token: %s", err)
			response.WriteHeader(403)
			return
		}
		chirp, err := cfg.database_queries.GetChirp(request.Context(), chirp_parse_id)
		if err != nil {
			log.Printf("Chirp not found: %s", err)
			response.WriteHeader(404)
			return
		}
		if id_to_test == chirp.UserID {
			err = cfg.database_queries.DeleteChirp(request.Context(), chirp_parse_id)
			if err != nil {
				log.Printf("Error deleting chirp: %s", err)
				response.WriteHeader(404)
				return
			}
			response.WriteHeader(204)
		} else {
			response.WriteHeader(403)
		}
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
	if request.URL.Query().Get("author_id") != "" {
		id, err := uuid.Parse(request.URL.Query().Get("author_id"))
		if err != nil {
			log.Printf("Error getting the id: %s", err)
			response.WriteHeader(401)
			return
		}
		all_chirps, err := cfg.database_queries.GetChirpsByUser(request.Context(), id)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			response.WriteHeader(401)
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
			response.WriteHeader(401)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(200)
		response.Write(data_list_of_chirps)
		return
	}
	if request.URL.Query().Get("sort") == "desc" {
		all_chirps, err := cfg.database_queries.GetChirpsDesc(request.Context())
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			response.WriteHeader(401)
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
	} else {
		all_chirps, err := cfg.database_queries.GetChirpsAsc(request.Context())
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			response.WriteHeader(401)
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
		ID          uuid.UUID `json:"id"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		Email       string    `json:"email"`
		Password    string    `json:"-"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
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
		ID:          database_user.ID,
		CreatedAt:   database_user.CreatedAt,
		UpdatedAt:   database_user.UpdatedAt,
		Email:       database_user.Email,
		Password:    hash_password,
		IsChirpyRed: database_user.IsChirpyRed.Bool,
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
