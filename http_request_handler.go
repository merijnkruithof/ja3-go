package main

import (
	"github.com/valyala/fasthttp"
)

// HandleRequest displays the JA3
func HandleRequest(ctx *fasthttp.RequestCtx) {
	ctx.Write([]byte("hi"))
}
