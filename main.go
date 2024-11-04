package main

import (
	"encoding/json"
	"github.com/projectdiscovery/tlsx/pkg/tlsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"log"
	"strings"
)

type Response struct {
	SelfSigned bool
	SubjectAN  []string
	IssuerOrg  string
}

func (receiver *Response) ToString() string {
	out, err := json.Marshal(receiver)
	if err != nil {
		panic(err)
	}
	return string(out)
}

var ANList []string
var domainMap map[string]bool

func main() {

	opts := &clients.Options{
		TLSVersion: true,
		Retries:    3,
		Expired:    true,
		ScanMode:   "auto",
	}

	service, err := tlsx.New(opts)
	if err != nil {
		panic(err)
	}
	resp, err := service.Connect("", "159.75.164.35", "8008")
	if err != nil {
		panic(err)
	}

	var respStr Response
	respStr.SelfSigned = resp.SelfSigned
	respStr.IssuerOrg = resp.IssuerOrg[0]

	if !resp.SelfSigned {
		log.Println(resp.IssuerOrg[0])
		domainMap = make(map[string]bool)
		if len(resp.SubjectAN) > 1 {
			for _, v := range resp.SubjectAN {
				if strings.HasPrefix(v, "*.") {
					tmpStr := strings.Replace(v, "*.", "", 1)

					if !domainMap[tmpStr] {
						domainMap[tmpStr] = true
						ANList = append(ANList, tmpStr)
					}

				} else {
					if !domainMap[v] {
						domainMap[v] = true
						ANList = append(ANList, v)
					}
				}
			}

			respStr.SubjectAN = ANList

		} else {
			respStr.SubjectAN = resp.SubjectAN
		}

	} else {
		respStr.SubjectAN = resp.SubjectAN
	}

	log.Println(respStr.ToString())
	//fmt.Printf("[%v] scan-mode:%-7v tls-version:%v self-signed:%v cipher:%v IssuerOrg:%v SubjectAN:%v\n", resp.Host, opts.ScanMode, resp.Version, resp.SelfSigned, resp.Cipher, resp.IssuerOrg[0], resp.SubjectAN)
}
