package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func main() {
	apiCfg := &apiConfig{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/validate_chirp", apiCfg.handler_validate_chirp)
	mux.HandleFunc("GET /api/healthz", handler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.handler_number_requests)
	mux.HandleFunc("POST /admin/reset", apiCfg.handler_reset_counter)
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

func (cfg *apiConfig) handler_validate_chirp(response http.ResponseWriter, request *http.Request) {
	type chirp_phrase struct {
		Body string `json:"body"`
	}
	type error_phrase struct {
		Error string `json:"error"`
	}
	type success_phrase struct {
		CleanedBody string `json:"cleaned_body"`
	}
	list_of_profane := []string{"kerfuffle", "sharbert", "fornax"}
	decoder := json.NewDecoder(request.Body)
	params := chirp_phrase{}
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
	} else {
		/*
			resp_body := success_phrase{
				Valid: true,
			}
			data, err := json.Marshal(resp_body)
			if err != nil {
				log.Printf("Error decoding parameters: %s", err)
				return
			}
		*/
		new_string := []string{}
		// lower_string := strings.ToLower(string(params.Body))
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
		resp_body := success_phrase{
			CleanedBody: returning_string,
		}
		data, err := json.Marshal(resp_body)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			return
		}
		response.WriteHeader(200)
		response.Header().Set("Content-Type", "application/json")
		response.Write(data)
	}
}

func (cfg *apiConfig) handler_reset_counter(response http.ResponseWriter, request *http.Request) {
	header := response.Header()
	header.Set("Content-Type", "text/plain; charset=utf-8")
	response.WriteHeader(200)
	// byte_message := []byte("OK")
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
