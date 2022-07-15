package main

import (
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
)

func main() {
	l := log.WithFields(log.Fields{
		"pkg": "server",
		"fn":  "main",
	})
	l.Info("start")
	// serve static files from /static
	r := mux.NewRouter()
	staticDir := os.Getenv("STATIC_DIR")
	if staticDir == "" {
		staticDir = "static"
	}
	r.PathPrefix("/").Handler(http.StripPrefix("/", http.FileServer(http.Dir(staticDir))))
	port := "80"
	if os.Getenv("PORT") != "" {
		port = os.Getenv("PORT")
	}
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "OPTIONS"},
		AllowCredentials: false,
		Debug:            false,
	})
	h := c.Handler(r)
	http.ListenAndServe(":"+port, h)
}
