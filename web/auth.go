package web

import (
	"net/http"
	"os"
	"time"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
)

// ViewFunc func
type ViewFunc func(http.ResponseWriter, *http.Request)

// Auth 验证Token是否已经通过
func Auth(f ViewFunc) ViewFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookieInWeb, err := r.Cookie(cookieName)
		if err != nil {
			// 从环境变量中读取 BASE_URL
			baseURL := os.Getenv("BASE_URL")
			if baseURL == "" {
				baseURL = "/" // 如果未设置 BASE_URL，则默认为根路径
			}

			// 确保 baseURL 以斜杠结尾
			if baseURL[len(baseURL)-1] != '/' {
				baseURL += "/"
			}

			http.Redirect(w, r, baseURL+"login", http.StatusTemporaryRedirect)
			return
		}

		conf, _ := config.GetConfigCached()

		// 禁止公网访问
		if conf.NotAllowWanAccess {
			if !util.IsPrivateNetwork(r.RemoteAddr) {
				w.WriteHeader(http.StatusForbidden)
				util.Log("%q 被禁止从公网访问", util.GetRequestIPStr(r))
				return
			}
		}

		// 验证token
		if cookieInSystem.Value != "" &&
			cookieInSystem.Value == cookieInWeb.Value &&
			cookieInSystem.Expires.After(time.Now()) {
			f(w, r) // 执行被装饰的函数
			return
		}

		// 从环境变量中读取 BASE_URL
		baseURL := os.Getenv("BASE_URL")
		if baseURL == "" {
			baseURL = "/" // 如果未设置 BASE_URL，则默认为根路径
		}

		// 确保 baseURL 以斜杠结尾
		if baseURL[len(baseURL)-1] != '/' {
			baseURL += "/"
		}

		http.Redirect(w, r, baseURL+"login", http.StatusTemporaryRedirect)
	}
}

// AuthAssert 保护静态等文件不被公网访问
func AuthAssert(f ViewFunc) ViewFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		conf, err := config.GetConfigCached()

		// 配置文件为空, 启动时间超过3小时禁止从公网访问
		if err != nil &&
			time.Since(startTime) > time.Duration(3*time.Hour) && !util.IsPrivateNetwork(r.RemoteAddr) {
			w.WriteHeader(http.StatusForbidden)
			util.Log("%q 配置文件为空, 超过3小时禁止从公网访问", util.GetRequestIPStr(r))
			return
		}

		// 禁止公网访问
		if conf.NotAllowWanAccess {
			if !util.IsPrivateNetwork(r.RemoteAddr) {
				w.WriteHeader(http.StatusForbidden)
				util.Log("%q 被禁止从公网访问", util.GetRequestIPStr(r))
				return
			}
		}

		f(w, r) // 执行被装饰的函数

	}
}
