package main

import (
	log "github.com/golang/glog"
	"html/template"
	"net/http"
)

var indexTmpl = template.Must(
	template.ParseFiles(
		"server/templates/_base.html",
		"server/templates/index.html",
	))

var errorTmpl = template.Must(
	template.ParseFiles(
		"server/templates/_base.html",
		"server/templates/error.html",
	))

func IsAdmin(r *http.Request) bool {
	return true
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	log.Infof("Handling %v", r.URL.String())
	tc := make(map[string]interface{})
	tc["username"] = "MyUsername"
	err := indexTmpl.Execute(w, tc)
	if err != nil {
		ErrorHandler(w, r, err)
		return
	}
}

func ErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	log.Infof("Error: %v\nfor request: %v\n", err, r)
	if IsAdmin(r) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tc := make(map[string]interface{})
	err = errorTmpl.Execute(w, tc)
	if err != nil {
		log.Infof("Error on error template: %v\n", err)
	}
}
