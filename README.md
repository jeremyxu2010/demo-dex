# 身份认证系统

读完[dex](https://github.com/dexidp/dex)的官方文档，感觉官方文档写得比较晦涩难懂，本项目尝试使用[dex](https://github.com/dexidp/dex)实现一个满足基本需求的身份认证系统，并加以简要说明。

## 如何运行

前提是已经搭建好了go语言的开发环境，并设置好了GOPATH。

然后按以下步骤运行本程序：

```bash
# 编译dexserver
$ make build-dexserver

# 编译dexclient
$ make build-dexclient

# 运行dexserver
$ make run-dexserver

# 运行dexclient
$ run-dexclient
```

然后用浏览器访问[http://127.0.0.1:8080](http://127.0.0.1:8080), 页面会自动跳转至`dexserver`的登录页面，输入用户名`admin@example.com`、密码`password`之后，会跳回`dexclient`的callback页面`http://127.0.0.1:8080/callback`。

## 技术细节说明

### dexserver

这里使用的`dexserver`是由官方代码直接编译得出的，没有修改任何代码。只不过使用了自定义的配置文件[dexserver-config.yaml](config/dexserver-config.yaml)，这里分析一下这个配置文件。

```yaml
# The base path of dex and the external name of the OpenID Connect service.
# This is the canonical URL that all clients MUST use to refer to dex. If a
# path is provided, dex's HTTP service will listen at a non-root URL.
issuer: http://127.0.0.1:5556/dex

# The storage configuration determines where dex stores its state. Supported
# options include SQL flavors and Kubernetes third party resources.
#
# See the storage document at Documentation/storage.md for further information.
storage:
  type: sqlite3
  config:
    file: config/dex.db

# Configuration for the HTTP endpoints.
web:
  http: 0.0.0.0:5556
  # Uncomment for HTTPS options.
  # https: 127.0.0.1:5554
  # tlsCert: /etc/dex/tls.crt
  # tlsKey: /etc/dex/tls.key

# Configuration for telemetry
telemetry:
  http: 0.0.0.0:5558

# Uncomment this block to enable the gRPC API. This values MUST be different
# from the HTTP endpoints.
# grpc:
#   addr: 127.0.0.1:5557
#  tlsCert: examples/grpc-client/server.crt
#  tlsKey: examples/grpc-client/server.key
#  tlsClientCA: /etc/dex/client.crt

# Uncomment this block to enable configuration for the expiration time durations.
# expiry:
#   signingKeys: "6h"
#   idTokens: "24h"

# Options for controlling the logger.
# logger:
#   level: "debug"
#   format: "text" # can also be "json"

# Uncomment this block to control which response types dex supports. For example
# the following response types enable the implicit flow for web-only clients.
# Defaults to ["code"], the code flow.
# oauth2:
#   responseTypes: ["code", "token", "id_token"]

oauth2:
  skipApprovalScreen: true

# Instead of reading from an external storage, use this list of clients.
#
# If this option isn't chosen clients may be added through the gRPC API.
staticClients:
- id: demo-dexclient
  redirectURIs:
  - 'http://127.0.0.1:8080/callback'
  name: 'Demo dex client'
  secret: ZXhhbXBsZS1hcHAtc2VjcmV0

connectors: []
# - type: mockCallback
#   id: mock
#   name: Example
# - type: oidc
#   id: google
#   name: Google
#   config:
#     issuer: https://accounts.google.com
#     # Connector config values starting with a "$" will read from the environment.
#     clientID: $GOOGLE_CLIENT_ID
#     clientSecret: $GOOGLE_CLIENT_SECRET
#     redirectURI: http://127.0.0.1:5556/dex/callback
#     hostedDomains:
#     - $GOOGLE_HOSTED_DOMAIN

# Let dex keep a list of passwords which can be used to login to dex.
enablePasswordDB: true

# A static list of passwords to login the end user. By identifying here, dex
# won't look in its underlying storage for passwords.
#
# If this option isn't chosen users may be added through the gRPC API.
# staticPasswords: 
# - email: "admin@example.com"
#   # bcrypt hash of the string "password"
#   hash: "$2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W"
#   username: "admin"
#   userID: "08a8684b-db88-4b73-90a9-3cd1661f5466"
```

`web`段配置的是`dexserver`的监听地址及HTTPS证书参数，`issuer`配置的是外部会访问到的系统URL，这两者一般要对应地设置。

`telemetry`段配置的是监控指标抓取地址，本例中`dexserver`启动完毕后，可访问[http://127.0.0.1:5558/metrics](http://127.0.0.1:5558/metrics)抓取到该`dexserver`的监控指标。

`storage`段配置的是`dexserver`的存储设置。`dexserver`在运行时跟踪`refresh_token`、`auth_code`、`keys`、`password`等的状态，因此需要将这些状态保存下来。[dex](https://github.com/dexidp/dex)提供了多种存储方案，如`etcd`、`CRDs`、`SQLite3`、`Postgres`、`MySQL`、`memory`，总有一款能满足需求。如果要其它需求，还可以参考[现有Storage](https://github.com/dexidp/dex/tree/master/storage)及[文档](https://github.com/dexidp/dex/blob/master/Documentation/storage.md#adding-a-new-storage-options)扩展一个。我这里使用的是比较简单的`SQLite3`Storage，提前插入了一条测试的用户数据：

```bash
sqlite3 config/dex.db
sqlite> insert info password values('admin@example.com', '$2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W', 'admin', '08a8684b-db88-4b73-90a9-3cd1661f5466');
sqlite> .quit
```

`oauth2.skipApprovalScreen`这个选项我设置成了`true`，这样就不会有提示用户同意的页面出现。

`staticClients`段配置的是该`dexserver`允许接入的`dexclient`信息，这个要跟`dexclient`那边的配置一致。

`connectors`段我并没有配置任何`Connector`。`Connector`是`dex`中一项重要特性，其可以将`dex`这个身份认证系统与其它身份认证系统串联起来。`dex`目前自带的`Connector`有`LDAP`、`GitHub`、`SAML 2.0`、`GitLab`、`OpenID Connect`、`LinkedIn`、`Microsoft`、`AuthProxy`、`Bitbucket Cloud`，基本上满足绝大部分需求，如果要扩展，参考某个[现成的Connector](https://github.com/dexidp/dex/tree/master/connector)实现即可。我这个示例里因为直接使用保存在DB里的帐户密码信息，因此只需要配置`enablePasswordDB`为`true`，就会自动使用上`passwordDB`这个`Connector`，`passwordDB`的实现代码见[这里](https://github.com/dexidp/dex/blob/master/server/server.go#L325)。

最近由于登录页面是由`dexserver`提供了，这里还将`dex`自带的[登录页面web端资源](web)带上了，具体的项目中根据场景对页面进行一些定制就可以了。

### dexclient

`dexclient`就很简单了，就两个go文件，重点是`cmd/dexclient/main.go`。

首先是根据一系列参数构造出`oidc.Provider`及`oidc.IDTokenVerifier`，这个后面获取认证系统的跳转地址、获取`id_token`、校验`id_token`都会用到:

```golang
...
            a.provider = provider
            a.verifier = provider.Verifier(&oidc.Config{ClientID: a.clientID})
```

然后声明处理三个请求地址，并启动Web Server：

```golang
			http.HandleFunc("/", a.handleIndex)
			http.HandleFunc("/login", a.handleLogin)
			http.HandleFunc(u.Path, a.handleCallback)

			switch listenURL.Scheme {
			case "http":
				log.Printf("listening on %s", listen)
				return http.ListenAndServe(listenURL.Host, nil)
			case "https":
				log.Printf("listening on %s", listen)
				return http.ListenAndServeTLS(listenURL.Host, tlsCert, tlsKey, nil)
			default:
				return fmt.Errorf("listen address %q is not using http or https", listen)
			}
```

很明显`handleIndex`就是WEB应用的主页，这里一般逻辑应该是检查用户的登录身份信息是否合法，如果不合法则跳至`dexserver`的登录页面。

```golang
var indexTmpl = template.Must(template.New("index.html").Parse(`<html>
  <!-- TODO Redirect to login page if not logged  -->
  <body>
    <form action="/login" method="post">
       <p>
         Authenticate for:<input type="text" name="cross_client" placeholder="list of client-ids">
       </p>
       <p>
         Extra scopes:<input type="text" name="extra_scopes" placeholder="list of scopes">
       </p>
       <p>
         Connector ID:<input type="text" name="connector_id" placeholder="connector id">
       </p>
       <p>
         Request offline access:<input type="checkbox" name="offline_access" value="yes" checked>
       </p>
       <input type="submit" value="Login" id="submitBtn">
    </form>
  </body>
  <script type="text/javascript">
    <!-- Redirect to login page -->
	document.getElementById("submitBtn").click();
  </script>
</html>`))
```

`handleLogin`根据浏览器发来的`cross_client`、`extra_scopes`、`connector_id`、`offline_access`参数构造出登录页跳转地址，并提示浏览器跳至该地址:

```golang
    ...
    if r.FormValue("offline_access") != "yes" {
		authCodeURL = a.oauth2Config(scopes).AuthCodeURL(exampleAppState)
	} else if a.offlineAsScope {
		scopes = append(scopes, "offline_access")
		authCodeURL = a.oauth2Config(scopes).AuthCodeURL(exampleAppState)
	} else {
		authCodeURL = a.oauth2Config(scopes).AuthCodeURL(exampleAppState, oauth2.AccessTypeOffline)
	}
	if connectorID != "" {
		authCodeURL = authCodeURL + "&connector_id=" + connectorID
	}

	http.Redirect(w, r, authCodeURL, http.StatusSeeOther)
```

`handleCallback`处理登录成功后的回调请求，其根据回调请求中的`code`参数，调用`dexserver`的相关接口换取包含用户身份信息的`Token`：

```golang
        code := r.FormValue("code")
		if code == "" {
			http.Error(w, fmt.Sprintf("no code in request: %q", r.Form), http.StatusBadRequest)
			return
		}
		if state := r.FormValue("state"); state != exampleAppState {
			http.Error(w, fmt.Sprintf("expected state %q got %q", exampleAppState, state), http.StatusBadRequest)
			return
		}
		token, err = oauth2Config.Exchange(ctx, code)
```

一般来说，会将该`Token`中的`id_token`进行适当的编码发回到浏览器中保存（以Cookie或WebStorage等方式），这样浏览器中就保存了用户的身份信息。

安全起见，`dexserver`签发的`id_token`有效期通常不会太长，这就需要`dexclient`凭借`Token`中的`refresh_token`隔段时间重新换取新的`Token`，并通过某种机制将新`Token`中的`id_token`重新发回浏览器端保存。以`refresh_token`重新换取新的`Token`的代码实现如下：

```golang
		t := &oauth2.Token{
			RefreshToken: refresh,
			Expiry:       time.Now().Add(-time.Hour),
		}
		token, err = oauth2Config.TokenSource(ctx, t).Token()
```

