package monitoring

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/Masterminds/semver"
	"github.com/openshift/backplane-cli/pkg/cli/config"
	"github.com/openshift/backplane-cli/pkg/utils"
	routev1typedclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	userv1typedclient "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"
	"github.com/pkg/browser"
	logger "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	ALERTMANAGER = "alertmanager"
	PROMETHEUS   = "prometheus"
	THANOS       = "thanos"
	GRAFANA      = "grafana"
)

var (
	MonitoringArgs struct {
		Browser    bool
		Namespace  string
		Selector   string
		Port       string
		OriginUrl  string
		ListenAddr string
	}
	ValidArgs = []string{PROMETHEUS, ALERTMANAGER, THANOS, GRAFANA}
)

func RunMonitoring(argv []string) error {

	// Handling flags [command line agruments]

	monitoringName := argv[0]

	cfg, err := clientcmd.BuildConfigFromFlags("", clientcmd.NewDefaultPathOptions().GetDefaultFilename())
	if err != nil {
		return err
	}

	// creates URL for serving
	if !strings.Contains(cfg.Host, "backplane/cluster") {
		return fmt.Errorf("the api server is not a backplane url, please make sure you login to the cluster using backplane")
	}
	murl := strings.Replace(cfg.Host, "backplane/cluster", fmt.Sprintf("backplane/%s", monitoringName), 1)
	murl = strings.TrimSuffix(murl, "/")
	mu, err := url.Parse(murl)
	if err != nil {
		return err
	}
	// creates OCM access token
	accessToken, err := utils.DefaultOCMInterface.GetOCMAccessToken()
	if err != nil {
		return err
	}

	//checks namespace
	if MonitoringArgs.Namespace == "openshift-monitoring" {
		//checks cluster version
		currentClusterInfo, err := utils.DefaultClusterUtils.GetBackplaneClusterFromConfig()
		if err != nil {
			return err
		}
		currentCluster, err := utils.DefaultOCMInterface.GetClusterInfoByID(currentClusterInfo.ClusterID)
		if err != nil {
			return err
		}
		clusterVersion := currentCluster.OpenshiftVersion()
		if clusterVersion != "" {
			version, err := semver.NewVersion(clusterVersion)
			if err != nil {
				return err
			}
			if version.Minor() >= 11 && (monitoringName == PROMETHEUS || monitoringName == ALERTMANAGER || monitoringName == GRAFANA) {
				return fmt.Errorf("this cluster's version is 4.11 or greater. Following version 4.11, Prometheus, AlertManager and Grafana monitoring UIs are deprecated, please use 'ocm backplane console' and use the metrics tab for the same")
			}
		}
	}

	isGrafana := monitoringName == GRAFANA
	hasNs := len(MonitoringArgs.Namespace) != 0
	hasAppSelector := len(MonitoringArgs.Selector) != 0
	hasPort := len(MonitoringArgs.Port) != 0
	hasUrl := len(MonitoringArgs.OriginUrl) != 0

	// serveUrl is the port-forward url we print to the user in the end.
	serveUrl, err := serveUrl(hasUrl, hasNs, cfg)
	if err != nil {
		return err
	}

	var name string
	if isGrafana {
		userInterface, err := userv1typedclient.NewForConfig(cfg)
		if err != nil {
			return err
		}

		user, err := userInterface.Users().Get(context.TODO(), "~", metav1.GetOptions{})
		if err != nil {
			return err
		}
		name = strings.Replace(user.Name, "system:serviceaccount:", "", 1)
	}

	// Test if the monitoring stack works, by sending a request to backend/backplane-api
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {

		log.Fatalf("connecting to server %v", err)
	}

	// Add http proxy transport
	proxyUrl, err := getProxyUrl()
	if err != nil {
		return err
	}
	if proxyUrl != "" {
		proxyUrl, err := url.Parse(proxyUrl)
		if err != nil {
			return err
		}
		http.DefaultTransport = &http.Transport{Proxy: http.ProxyURL(proxyUrl)}

		logger.Debugf("Using backplane Proxy URL: %s\n", proxyUrl)
	}

	req = setProxyRequest(req, mu, name, accessToken, isGrafana, hasNs, hasAppSelector, hasPort)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		responseBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf(string(responseBody))
	}

	// If the above test pass, we will construct a reverse proxy for the user
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			setProxyRequest(req, mu, name, accessToken, isGrafana, hasNs, hasAppSelector, hasPort)
		},
	}

	// serve the proxy
	var addr string
	if len(MonitoringArgs.ListenAddr) > 0 {
		// net.Listen will validate the addr later
		addr = MonitoringArgs.ListenAddr
	} else {
		port, err := utils.GetFreePort()
		if err != nil {
			return err
		}
		addr = fmt.Sprintf("127.0.0.1:%d", port)
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	serveUrl.Host = addr

	if MonitoringArgs.Browser {
		err = browser.OpenURL(serveUrl.String())
		if err != nil {
			logger.Warnf("failed opening a browser: %s", err)
		}
	}

	if !MonitoringArgs.Browser {
		fmt.Printf("Serving %s at %s\n", monitoringName, serveUrl.String())
	}

	//#nosec G114 -- This is a local reverse proxy, not a public facing server. We don't need to set timeouts.
	return http.Serve(l, proxy)
}

// Setting Headers, accesToken, port and selector
func setProxyRequest(
	req *http.Request,
	proxyUrl *url.URL,
	userName string,
	accessToken *string,
	isGrafana bool,
	hasNs bool,
	hasAppSelector bool,
	hasPort bool,
) *http.Request {
	req.URL.Scheme = "https"
	req.Host = proxyUrl.Host
	req.URL.Host = proxyUrl.Host
	req.URL.Path = singleJoiningSlash(proxyUrl.Path, req.URL.Path)
	if _, ok := req.Header["User-Agent"]; !ok {
		// explicitly disable User-Agent so it's not set to default value
		req.Header.Set("User-Agent", "")
	}
	if isGrafana {
		req.Header.Set("x-forwarded-user", userName)
	}
	if hasNs {
		req.Header.Set("x-namespace", MonitoringArgs.Namespace)
	}
	if hasAppSelector {
		req.Header.Set("x-selector", MonitoringArgs.Selector)
	}
	if hasPort {
		req.Header.Set("x-port", MonitoringArgs.Port)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", *accessToken))

	return req
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// Check if a route of the originUrl exist in the namespace.
// TODO add unit tests
func hasMatchRoute(namespace string, originUrl *url.URL, cfg *restclient.Config) bool {
	routeInterface, err := routev1typedclient.NewForConfig(cfg)
	if err != nil {
		logger.Warnf("cannot create route client-go interface %s", err)
		return false
	}
	routes, err := routeInterface.Routes(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		logger.Warnf("cannot get routes: %s", err)
		return false
	}
	for _, rt := range routes.Items {
		ri := rt.Status.Ingress
		for _, ig := range ri {
			logger.Debugf("found route ingress %s", ig.Host)
			if utils.MatchBaseDomain(originUrl.Hostname(), ig.Host) {
				return true
			}
		}
	}
	return false
}

// serveUrl returns the port-forward url to the route
func serveUrl(hasUrl, hasNs bool, cfg *restclient.Config) (*url.URL, error) {
	serveUrl := &url.URL{
		Scheme: "http",
	}

	if hasUrl {
		originUrl, err := url.Parse(MonitoringArgs.OriginUrl)
		if err != nil {
			return nil, err
		}
		// verify if the provided url matches the current login cluster
		currentClusterInfo, err := utils.DefaultClusterUtils.GetBackplaneClusterFromConfig()
		if err != nil {
			return nil, err
		}
		currentCluster, err := utils.DefaultOCMInterface.GetClusterInfoByID(currentClusterInfo.ClusterID)
		if err != nil {
			return nil, err
		}
		baseDomain := currentCluster.DNS().BaseDomain()
		if !utils.MatchBaseDomain(originUrl.Hostname(), baseDomain) {
			return nil, fmt.Errorf("the basedomain %s of the current logged cluster %s does not match the provided url, please login to the corresponding cluster first",
				baseDomain, currentClusterInfo.ClusterID)
		}
		// verify if the route exists in the given namespace
		if !hasNs {
			// namespace has a default value, prompt error in case user specify it with blank string.
			return nil, fmt.Errorf("namepace should not be blank, please specify namespace by --namespace")
		}

		if !hasMatchRoute(MonitoringArgs.Namespace, originUrl, cfg) {
			return nil, fmt.Errorf("cannot find a matching route in namespace %s for the given url, please specify a correct namespace by --namespace",
				MonitoringArgs.Namespace)
		}

		// append path and query to the url printed later
		serveUrl.Path = originUrl.Path
		serveUrl.RawQuery = originUrl.RawQuery
		serveUrl.Fragment = originUrl.Fragment
		return serveUrl, nil
	}

	return serveUrl, nil
}

// Get the proxy url
func getProxyUrl() (proxyUrl string, err error) {
	bpConfig, err := config.GetBackplaneConfiguration()

	if err != nil {
		return "", err
	}

	proxyUrl = bpConfig.ProxyURL

	return proxyUrl, nil
}
