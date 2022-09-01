package goarch2

import "embed"

//go:embed template
var Efs embed.FS

// template files
var IndexFile string = "template/index.html"
var HeaderFile string = "template/header.html"
var GitLabFile string = "template/gitlab.html"
var LoggedInFile string = "template/loggedIn.html"
var RegisterFile string = "template/register.html"
var PartialRegisterFile string = "template/partialRegister.html"

// template data
type IndexData struct {
	Header   HeaderData
	GitLab   GitLabData
	LoggedIn LoggedInData
	Register RegisterData
}

type PartialRegisterData struct {
	Header   HeaderData
	Register RegisterData
}

type LoggedInData struct {
	User string
}

type HeaderData struct {
	Title string
}

type RegisterData struct {
	Action string
	Sid    string
	Email  string
	Name   string
}

type GitLabData struct {
	Action string
}

type User struct {
	Name     string
	Email    string
	Password []byte
	ID       string
}
