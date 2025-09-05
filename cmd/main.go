package main

import "github.com/adanyl0v/go-todo-list/internal/app"

func main() {
	app.InitDefaultLogger()
	app.MustReadEnv()
	app.MustInitApplicationLogger()

	app.MustConnectPostgres()
	defer app.DisconnectPostgres()

	app.MustListenAndServeHTTP()
}
