package eg8145v5

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chickenzord/go-huawei-client/pkg/js"
)

type Client struct {
	jar *cookiejar.Jar
	h   *http.Client
	m   sync.Mutex

	baseURL   string
	userAgent string
	username  string
	password  string
}

// newClient
// Create a new client.
func newClient(baseURL, username, password string) *Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		panic(err)
	}

	jar.SetCookies(u, []*http.Cookie{
		{
			Name:  "Cookie",
			Value: "body:Language:english:id=-1",
		},
	})

	return &Client{
		userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0",
		baseURL:   baseURL,
		username:  username,
		password:  password,

		jar: jar,
		h: &http.Client{
			Jar:       jar,
			Timeout:   5 * time.Second,
			Transport: http.DefaultTransport,
		},
		m: sync.Mutex{},
	}
}

// NewClient
// Create a new client.
func NewClient(cfg Config) *Client {
	return newClient(cfg.URL, cfg.Username, cfg.Password)
}

// GetHardwareToken
// Get the generated random number to be used in authentication
func (c *Client) GetHardwareToken() (string, error) {
	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/asp/GetRandCount.asp", nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Referer", c.baseURL)

	res, err := c.h.Do(req)
	if err != nil {
		return "", err
	}

	token, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	rawToken := strings.TrimSpace(string(token))

	return rawToken[len(rawToken)-48:], nil
}

func (c *Client) Validate() error {
	if c.baseURL == "" {
		return fmt.Errorf("URL is not set")
	}

	if c.username == "" {
		return fmt.Errorf("username is not set")
	}

	if c.password == "" {
		return fmt.Errorf("password is not set")
	}

	return nil
}

// Login
// Authenticate using saved username/password.
// Authentication cookies will be persisted in the lifetime of Client.
func (c *Client) Login() error {
	c.m.Lock()
	defer c.m.Unlock()

	if err := c.Validate(); err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	hwToken, err := c.GetHardwareToken()
	if err != nil {
		return err
	}

	params := url.Values{}
	params.Set("UserName", c.username)
	params.Set("PassWord", base64.StdEncoding.EncodeToString([]byte(c.password)))
	params.Set("Language", "english")
	params.Set("x.X_HW_Token", hwToken)

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/login.cgi", strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Origin", c.baseURL)
	req.Header.Set("Referer", c.baseURL+"/")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(params.Encode())))
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")

	res, err := c.h.Do(req)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK {
		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}

		return fmt.Errorf("http %d: %s", res.StatusCode, string(resBody))
	}

	if len(res.Cookies()) == 0 {
		return fmt.Errorf("login failed")
	}

	return nil
}

// Logout
// End Client's session and clear authentication cookies.
func (c *Client) Logout() error {
	c.m.Lock()
	defer c.m.Unlock()

	if err := c.Validate(); err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	hwToken, err := c.GetHardwareToken()
	if err != nil {
		return err
	}

	params := url.Values{}
	params.Set("x.X_HW_Token", hwToken)

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/logout.cgi?RequestFile=html/logout.html", strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Origin", c.baseURL)
	req.Header.Set("Referer", c.baseURL+"/index.asp")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(params.Encode())))
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")

	res, err := c.h.Do(req)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}

		return err
	}

	if res.StatusCode != http.StatusOK {
		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}

		return fmt.Errorf("http %d: %s", res.StatusCode, string(resBody))
	}

	return nil
}

// Session
// Run the fnSession function wrapped in Login and Logout
func (c *Client) Session(fnSession func(c *Client) error) error {
	if err := c.Login(); err != nil {
		return err
	}
	defer c.Logout()

	if err := fnSession(c); err != nil {
		return err
	}

	return nil
}

// ListUserDevices
// Get all user devices. Client must be authenticated.
func (c *Client) ListUserDevices() ([]UserDevice, error) {
	c.m.Lock()
	defer c.m.Unlock()

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/html/bbsp/common/GetLanUserDevInfo.asp", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Referer", c.baseURL+"/html/bbsp/userdevinfo/userdevinfo.asp")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	res, err := c.h.Do(req)
	if err != nil {
		return nil, err
	}

	jsPayload, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	jsContent := string(jsPayload)
	s := js.Script{
		Name:    "userdevinfo.asp.js",
		Content: jsContent,
	}

	var devices []*UserDevice

	if err := s.EvalJSON(&devices, "GetUserDevInfoList"); err != nil {
		return nil, err
	}

	var result []UserDevice

	for _, dev := range devices {
		if dev != nil {
			result = append(result, *dev)
		}
	}

	return result, nil
}

// GetResourceUsage
// Get current resource usages. Client must be authenticated.
func (c *Client) GetResourceUsage() (*ResourceUsage, error) {
	c.m.Lock()
	defer c.m.Unlock()

	req, err := http.NewRequest(http.MethodGet, c.baseURL+"/html/ssmp/deviceinfo/deviceinfo.asp", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Referer", c.baseURL)

	res, err := c.h.Do(req)
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, err
	}

	scriptContent := doc.Find("script:not([src])").First().Text()
	if scriptContent == "" {
		return nil, fmt.Errorf("cannot find the script")
	}

	s := js.Script{
		Name:    "deviceinfo.asp.js",
		Content: scriptContent + ResourceUsageFuncScript,
	}

	var usage ResourceUsage

	if err := s.EvalJSON(&usage, ResourceUsageFuncName); err != nil {
		return nil, err
	}

	return &usage, nil
}
func (c Client) getPageEmbeddedHWToken(page string) (*string, error) {

	_, err := c.GetHardwareToken()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, c.baseURL+page, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Referer", c.baseURL)

	resp, err := c.h.Do(req)
	if err != nil {
		return nil, err
	}
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	htmlSrc := string(all)
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlSrc))
	if err != nil {
		return nil, err
	}
	// <input type="hidden" name="onttoken" id="hwonttoken" value="30e8637001339c6fbf119119c41a8e065a9d32304ce74f4f">
	hwToken, exists := doc.Find("input#hwonttoken").First().Attr("value")
	if !exists {
		return nil, errors.New("hwonttoken not found")
	}
	return &hwToken, nil
}

func (c *Client) GetAllStaticDnsHosts() ([]StaticDnsHost, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.getAllStaticDNSHosts()

}
func (c *Client) getAllStaticDNSHosts() ([]StaticDnsHost, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+"/html/bbsp/common/dnshostslist.asp", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-GB,en-US;q=0.9,en;q=0.8")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Referer", c.baseURL+"/html/bbsp/dnsconfiguration/dnshosts.asp")
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.h.Do(req)
	if err != nil {
		return nil, err
	}
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// Regex pattern to match DnsHostsItemClass instances
	pattern := `new\s+DnsHostsItemClass\("([^"]+)","([^"]+)","([^"]+)"\)`
	re := regexp.MustCompile(pattern)
	matches := re.FindAllStringSubmatch(string(all), -1)

	if matches == nil {
		return nil, errors.New("no DNS hosts found")
	}

	var dnsHostsList []StaticDnsHost
	for _, match := range matches {
		// Unescape the escaped characters
		domainName := strings.ReplaceAll(match[3], `\x2e`, ".")
		ipAddress := strings.ReplaceAll(match[2], `\x2e`, ".")
		host := StaticDnsHost{
			DomainName: domainName,
			IPAddress:  ipAddress,
		}
		dnsHostsList = append(dnsHostsList, host)
	}

	return dnsHostsList, nil
}
func (c *Client) dnsHostOperation(operation string, host StaticDnsHost) error {
	c.m.Lock()
	defer c.m.Unlock()
	hwToken, err := c.getPageEmbeddedHWToken("/html/bbsp/dnsconfiguration/dnshosts.asp")
	if err != nil {
		return err
	}
	data := url.Values{}
	data.Set("x.IPAddress", host.IPAddress)
	data.Set("x.DomainName", host.DomainName)
	data.Set("x.X_HW_Token", *hwToken)
	req, err := http.NewRequest(http.MethodPost, c.baseURL+operation, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Referer", c.baseURL+"/html/bbsp/dnsconfiguration/dnshosts.asp")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Origin", c.baseURL)
	req.Header.Set("Accept-Language", "en-GB,en-US;q=0.9,en;q=0.8")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Accept", "*/*")

	if err != nil {
		return err
	}
	resp, err := c.h.Do(req)
	if err != nil {
		return err
	}
	// Very weird, but for some reason the router returns 404 when the host is added successfully
	if resp.StatusCode != http.StatusNotFound {
		return errors.New("failed to add DNS host (Expected status 404, but got " + strconv.Itoa(resp.StatusCode) + ")")
	}
	return nil
}

func (c *Client) AddDnsHost(host StaticDnsHost) error {
	return c.dnsHostOperation("/add.cgi?x=InternetGatewayDevice.X_HW_DNS.HOSTS&RequestFile=html/ipv6/not_find_file.asp", host)
}

func (c *Client) SetDnsHost(host StaticDnsHost, index int) error {
	return c.dnsHostOperation("/set.cgi?x=InternetGatewayDevice.X_HW_DNS.HOSTS."+strconv.Itoa(index+1)+"&RequestFile=html/ipv6/not_find_file.asp", host)
}
