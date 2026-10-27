// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
package openserverless

import (
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"
)

// Behind a corporate proxy, requests to the OpenServerless apihost must bypass
// the proxy: the apihost is usually local (http://miniops.me resolves to
// 127.0.0.1) or inside the user's network, and the proxy cannot reach it.
// Go, bun and curl all route a hostname through the proxy unless it is listed
// in NO_PROXY, and they only match by name, not by the address it resolves to.
// Since ops knows the apihost, it adds it to NO_PROXY for itself and for every
// process it spawns (wsk, bun, curl in tasks).

var proxyEnvVars = []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"}

// ensureApiHostNoProxy adds the configured apihost(s) to NO_PROXY and no_proxy
// when a proxy is configured. It is idempotent and safe to call several times:
// once early, before any network call, and again after the config env vars
// (OPERATOR_CONFIG_APIHOST) are loaded.
func ensureApiHostNoProxy() {
	if !proxyConfigured() {
		return
	}
	hosts := apiHostNames(os.Getenv("OPS_APIHOST"), os.Getenv("OPERATOR_CONFIG_APIHOST"), wskPropsAPIHost())
	if len(hosts) == 0 {
		return
	}
	setNoProxy(hosts...)
}

// ensureLoginNoProxy adds the apihost given to `ops -login <apihost>` to NO_PROXY.
// args are the command line arguments after the program name. It must run before
// the first network call of the process (tasks download, update check), because
// Go reads the proxy environment only once.
func ensureLoginNoProxy(args []string) {
	if len(args) == 0 || (args[0] != "-l" && args[0] != "-login") {
		return
	}
	ensureNoProxyFor(loginApiHostArg(args[1:]))
}

// ensureNoProxyFor adds the given apihost to NO_PROXY, for commands that take
// the apihost as an argument (ops -login <apihost>).
func ensureNoProxyFor(apihost string) {
	if !proxyConfigured() {
		return
	}
	hosts := apiHostNames(apihost)
	if len(hosts) == 0 {
		return
	}
	setNoProxy(hosts...)
}

func setNoProxy(hosts ...string) {
	merged := mergeNoProxy(os.Getenv("NO_PROXY"), os.Getenv("no_proxy"), hosts...)
	//nolint:errcheck
	os.Setenv("NO_PROXY", merged)
	//nolint:errcheck
	os.Setenv("no_proxy", merged)
	trace("NO_PROXY", merged)
}

func proxyConfigured() bool {
	for _, name := range proxyEnvVars {
		if os.Getenv(name) != "" {
			return true
		}
	}
	return false
}

// apiHostNames extracts the host names from apihost URLs, dropping empty,
// unparsable and duplicate values.
func apiHostNames(apihosts ...string) []string {
	var hosts []string
	for _, raw := range apihosts {
		host := apiHostName(raw)
		if host == "" || containsFold(hosts, host) {
			continue
		}
		hosts = append(hosts, host)
	}
	return hosts
}

// apiHostName returns the bare host of an apihost such as "http://miniops.me",
// "https://api.example.com:443/" or "api.example.com", or "" if none.
func apiHostName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if host == "" {
		return ""
	}
	// an IP address is fine as is; a wildcard or anything odd is not a host
	if net.ParseIP(host) == nil && strings.ContainsAny(host, " *") {
		return ""
	}
	return host
}

// mergeNoProxy joins the entries of NO_PROXY and no_proxy and appends the hosts
// that are not yet present, so that neither spelling shadows the other.
func mergeNoProxy(upper, lower string, hosts ...string) string {
	var entries []string
	for _, list := range []string{upper, lower} {
		for _, e := range strings.Split(list, ",") {
			e = strings.TrimSpace(e)
			if e != "" && !containsFold(entries, e) {
				entries = append(entries, e)
			}
		}
	}
	for _, h := range hosts {
		if h != "" && !containsFold(entries, h) {
			entries = append(entries, h)
		}
	}
	return strings.Join(entries, ",")
}

func containsFold(list []string, s string) bool {
	for _, e := range list {
		if strings.EqualFold(e, s) {
			return true
		}
	}
	return false
}

// wskPropsAPIHost returns the APIHOST stored in the wsk properties file
// (WSK_CONFIG_FILE or ~/.wskprops), or "" if not available.
func wskPropsAPIHost() string {
	wskProps := os.Getenv("WSK_CONFIG_FILE")
	if wskProps == "" {
		home, err := homedir.Expand("~")
		if err != nil {
			return ""
		}
		wskProps = filepath.Join(home, ".wskprops")
	}
	content, err := os.ReadFile(wskProps)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(content), "\n") {
		if value, ok := strings.CutPrefix(line, "APIHOST="); ok {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// loginApiHostArg returns the apihost passed to `ops -login [options] <apihost> [<user>]`,
// mirroring auth.LoginCmd: OPS_APIHOST wins, otherwise the first positional argument.
// args are the arguments after "-login".
func loginApiHostArg(args []string) string {
	if env := os.Getenv("OPS_APIHOST"); env != "" {
		return env
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			return arg
		}
		// flags with a separate value: -sso-flow device, --sso-username name
		name := strings.TrimLeft(arg, "-")
		if (name == "sso-flow" || name == "sso-username") && !strings.Contains(arg, "=") {
			i++
		}
	}
	return ""
}
