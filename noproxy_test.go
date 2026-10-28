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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApiHostName(t *testing.T) {
	cases := map[string]string{
		"http://miniops.me":                  "miniops.me",
		"https://api.example.com:443/":       "api.example.com",
		"  https://api.example.com/api/v1  ": "api.example.com",
		"api.example.com":                    "api.example.com",
		"api.example.com:8080":               "api.example.com",
		"http://user:pw@api.example.com":     "api.example.com",
		"http://127.0.0.1:3233":              "127.0.0.1",
		"http://[::1]:3233":                  "::1",
		"":                                   "",
		"   ":                                "",
		"http://":                            "",
		"http://bad host":                    "",
		"://nohost":                          "",
	}
	for in, want := range cases {
		require.Equal(t, want, apiHostName(in), "input %q", in)
	}
}

func TestApiHostNames(t *testing.T) {
	got := apiHostNames("http://miniops.me", "", "MINIOPS.ME", "https://api.example.com", "http://miniops.me/api")
	require.Equal(t, []string{"miniops.me", "api.example.com"}, got)
	require.Empty(t, apiHostNames("", "   "))
}

func TestMergeNoProxy(t *testing.T) {
	// empty lists
	require.Equal(t, "miniops.me", mergeNoProxy("", "", "miniops.me"))
	// appended after existing entries
	require.Equal(t, "localhost,127.0.0.1,miniops.me", mergeNoProxy("localhost,127.0.0.1", "", "miniops.me"))
	// both spellings are merged, no duplicates, whitespace trimmed
	require.Equal(t, "localhost,127.0.0.1,.corp.internal,miniops.me",
		mergeNoProxy("localhost, 127.0.0.1", "127.0.0.1,.corp.internal,", "miniops.me"))
	// already present (case-insensitive): unchanged
	require.Equal(t, "localhost,MiniOps.me", mergeNoProxy("localhost,MiniOps.me", "", "miniops.me"))
	// no hosts: still a clean merge
	require.Equal(t, "a,b", mergeNoProxy("a", "b"))
}

// stubDNS makes name resolution deterministic: names map to the given addresses,
// unknown names fail to resolve.
func stubDNS(t *testing.T, table map[string][]string) {
	orig := lookupHost
	lookupHost = func(host string) ([]string, error) {
		if addrs, ok := table[strings.ToLower(host)]; ok {
			return addrs, nil
		}
		return nil, errors.New("no such host: " + host)
	}
	t.Cleanup(func() { lookupHost = orig })
}

func TestIsLocalHost(t *testing.T) {
	stubDNS(t, map[string][]string{
		"miniops.me":        {"127.0.0.1"},
		"s3.miniops.me":     {"64:ff9b::7f00:1", "127.0.0.1"}, // DNS64 network
		"nat64.example":     {"64:ff9b::7f00:1"},
		"lan.corp.internal": {"10.20.30.40"},
		"cloud.example.com": {"203.0.113.10"},
		"mixed.example.com": {"203.0.113.10", "192.168.1.5"},
	})
	local := []string{
		"localhost", "LOCALHOST", "127.0.0.1", "::1", "0.0.0.0",
		"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "fd00::1", "fe80::1",
		"miniops.me", "s3.miniops.me", "nat64.example", "lan.corp.internal", "mixed.example.com",
	}
	for _, h := range local {
		require.True(t, isLocalHost(h), "%q should be local", h)
	}
	remote := []string{"8.8.8.8", "203.0.113.10", "2001:db8::1", "172.32.0.1", "cloud.example.com", "unresolvable.example"}
	for _, h := range remote {
		require.False(t, isLocalHost(h), "%q should not be local", h)
	}
	require.Equal(t, []string{"miniops.me", "10.0.0.1"}, localHosts([]string{"miniops.me", "cloud.example.com", "10.0.0.1", "unresolvable.example"}))
}

func clearProxyEnv(t *testing.T) {
	for _, name := range append([]string{"NO_PROXY", "no_proxy", "OPS_APIHOST", "OPERATOR_CONFIG_APIHOST"}, proxyEnvVars...) {
		t.Setenv(name, "")
		os.Unsetenv(name)
	}
}

func TestEnsureApiHostNoProxy(t *testing.T) {
	clearProxyEnv(t)
	stubDNS(t, map[string][]string{
		"miniops.me":        {"127.0.0.1"},
		"cloud.example.com": {"10.0.0.5"},
		"wsk.example.com":   {"192.168.0.9"},
	})
	// wskprops in a temp file so the test does not depend on ~/.wskprops
	wskProps := filepath.Join(t.TempDir(), "wskprops")
	t.Setenv("WSK_CONFIG_FILE", wskProps)

	// no proxy configured: nothing happens
	t.Setenv("OPERATOR_CONFIG_APIHOST", "http://miniops.me")
	ensureApiHostNoProxy()
	require.Equal(t, "", os.Getenv("NO_PROXY"))
	require.Equal(t, "", os.Getenv("no_proxy"))

	// proxy configured: the apihost is appended to both spellings
	t.Setenv("HTTPS_PROXY", "http://proxy.corp:3128")
	t.Setenv("NO_PROXY", "localhost,127.0.0.1")
	ensureApiHostNoProxy()
	require.Equal(t, "localhost,127.0.0.1,miniops.me", os.Getenv("NO_PROXY"))
	require.Equal(t, "localhost,127.0.0.1,miniops.me", os.Getenv("no_proxy"))

	// idempotent
	ensureApiHostNoProxy()
	require.Equal(t, "localhost,127.0.0.1,miniops.me", os.Getenv("NO_PROXY"))

	// apihost from OPS_APIHOST and from the wsk properties file are added too
	t.Setenv("OPS_APIHOST", "https://cloud.example.com")
	require.NoError(t, os.WriteFile(wskProps, []byte("APIHOST=http://wsk.example.com\nAUTH=x:y\n"), 0600))
	ensureApiHostNoProxy()
	require.Equal(t, "localhost,127.0.0.1,miniops.me,cloud.example.com,wsk.example.com", os.Getenv("NO_PROXY"))

	// lowercase-only configuration is preserved, not shadowed
	clearProxyEnv(t)
	t.Setenv("http_proxy", "http://proxy.corp:3128")
	t.Setenv("no_proxy", ".corp.internal")
	t.Setenv("OPERATOR_CONFIG_APIHOST", "http://miniops.me")
	require.NoError(t, os.Remove(wskProps))
	ensureApiHostNoProxy()
	require.Equal(t, ".corp.internal,miniops.me", os.Getenv("NO_PROXY"))
	require.Equal(t, ".corp.internal,miniops.me", os.Getenv("no_proxy"))

	// no apihost known: nothing happens
	clearProxyEnv(t)
	t.Setenv("HTTP_PROXY", "http://proxy.corp:3128")
	ensureApiHostNoProxy()
	require.Equal(t, "", os.Getenv("NO_PROXY"))

	// a remote apihost keeps going through the proxy: NO_PROXY untouched
	stubDNS(t, map[string][]string{"api.example.com": {"203.0.113.10"}})
	t.Setenv("OPS_APIHOST", "https://api.example.com")
	t.Setenv("NO_PROXY", "localhost")
	ensureApiHostNoProxy()
	require.Equal(t, "localhost", os.Getenv("NO_PROXY"))
	require.Equal(t, "", os.Getenv("no_proxy"))
}

func TestLoginApiHostArg(t *testing.T) {
	clearProxyEnv(t)
	require.Equal(t, "http://miniops.me", loginApiHostArg([]string{"http://miniops.me"}))
	require.Equal(t, "http://miniops.me", loginApiHostArg([]string{"http://miniops.me", "user"}))
	require.Equal(t, "http://miniops.me", loginApiHostArg([]string{"-sso-flow", "device", "http://miniops.me", "user"}))
	require.Equal(t, "http://miniops.me", loginApiHostArg([]string{"--sso-username=bob", "http://miniops.me"}))
	require.Equal(t, "http://miniops.me", loginApiHostArg([]string{"--sso-username", "bob", "-h", "http://miniops.me"}))
	require.Equal(t, "", loginApiHostArg([]string{"-sso-flow", "device"}))
	require.Equal(t, "", loginApiHostArg(nil))

	// OPS_APIHOST wins and the positional is the user
	t.Setenv("OPS_APIHOST", "https://cloud.example.com")
	require.Equal(t, "https://cloud.example.com", loginApiHostArg([]string{"user"}))
}

func TestEnsureLoginNoProxy(t *testing.T) {
	clearProxyEnv(t)
	stubDNS(t, map[string][]string{"miniops.me": {"127.0.0.1"}, "cloud.example.com": {"172.20.0.1"}})
	t.Setenv("HTTP_PROXY", "http://proxy.corp:3128")

	// not a login: nothing happens
	ensureLoginNoProxy([]string{"-wsk", "action", "list"})
	ensureLoginNoProxy([]string{"setup", "devcluster"})
	ensureLoginNoProxy(nil)
	require.Equal(t, "", os.Getenv("NO_PROXY"))

	ensureLoginNoProxy([]string{"-login", "http://miniops.me", "user"})
	require.Equal(t, "miniops.me", os.Getenv("NO_PROXY"))

	ensureLoginNoProxy([]string{"-l", "-sso-flow", "device", "https://cloud.example.com"})
	require.Equal(t, "miniops.me,cloud.example.com", os.Getenv("NO_PROXY"))
}

func TestEnsureNoProxyFor(t *testing.T) {
	clearProxyEnv(t)
	stubDNS(t, map[string][]string{"miniops.me": {"127.0.0.1"}, "cloud.example.com": {"203.0.113.10"}})
	ensureNoProxyFor("http://miniops.me")
	require.Equal(t, "", os.Getenv("NO_PROXY"), "no proxy configured")

	t.Setenv("HTTP_PROXY", "http://proxy.corp:3128")
	ensureNoProxyFor("http://miniops.me")
	require.Equal(t, "miniops.me", os.Getenv("NO_PROXY"))
	require.Equal(t, "miniops.me", os.Getenv("no_proxy"))

	ensureNoProxyFor("")
	require.Equal(t, "miniops.me", os.Getenv("NO_PROXY"))

	// remote apihost: not added
	ensureNoProxyFor("https://cloud.example.com")
	require.Equal(t, "miniops.me", os.Getenv("NO_PROXY"))
}
