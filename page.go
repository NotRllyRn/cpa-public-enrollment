package main

import _ "embed"

//go:embed web/index.html
var page string

//go:embed web/app.js
var script string

//go:embed web/enroll.css
var stylesheet string
