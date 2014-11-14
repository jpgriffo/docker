package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"

	"github.com/docker/docker/api"
	"github.com/docker/docker/api/client"
	"github.com/docker/docker/dockerversion"
	"github.com/docker/docker/pkg/log"
	flag "github.com/docker/docker/pkg/mflag"
	"github.com/docker/docker/reexec"
	"github.com/docker/docker/utils"
)

func main() {
	if reexec.Init() {
		return
	}
	flag.Parse()
	// FIXME: validate daemon flags here

	if *flVersion {
		showVersion()
		return
	}
	if *flDebug {
		os.Setenv("DEBUG", "1")
	}

	// Backwards compatibility for deprecated --tls and --tlsverify options
	if *flTls || *flTlsVerify {
		*flAuth = "cert"

		// Backwards compatibility for --tlscacert
		if *flCa != "" {
			*flAuthCa = *flCa
		}
		// Backwards compatibility for --tlscert
		if *flCert != "" {
			*flAuthCert = *flCert
		}
		// Backwards compatibility for --tlskey
		if *flKey != "" {
			*flAuthKey = *flKey
		}

		// Only verify against a CA if --tlsverify is set
		if !*flTlsVerify {
			*flAuthCa = ""
		}
	}

	if len(flHosts) == 0 {
		defaultHost := os.Getenv("DOCKER_HOST")
		if defaultHost == "" || *flDaemon {
			// If we do not have a host, default to unix socket
			defaultHost = fmt.Sprintf("unix://%s", api.DEFAULTUNIXSOCKET)
		}
		defaultHost, err := api.ValidateHost(defaultHost)
		if err != nil {
			log.Fatal(err)
		}
		flHosts = append(flHosts, defaultHost)
	}

	if *flDaemon {
		mainDaemon()
		return
	}

	if len(flHosts) > 1 {
		log.Fatal("Please specify only one -H")
	}
	protoAddrParts := strings.SplitN(flHosts[0], "://", 2)
	proto, addr := protoAddrParts[0], protoAddrParts[1]

	trustKey, err := api.LoadOrCreateTrustKey(*flTrustKey)
	if err != nil {
		log.Fatal(err)
	}

	var tlsConfig *tls.Config

	if proto != "unix" {
		switch *flAuth {
		case "identity":
			if tlsConfig, err = client.NewIdentityAuthTLSConfig(trustKey, *flTrustHosts, proto, addr); err != nil {
				log.Fatal(err)
			}
		case "cert":
			if tlsConfig, err = client.NewCertAuthTLSConfig(*flAuthCa, *flAuthCert, *flAuthKey); err != nil {
				log.Fatal(err)
			}
		case "none":
			tlsConfig = nil
		default:
			log.Fatalf("Unknown auth method: %s", *flAuth)
		}
	}

	cli := client.NewDockerCli(os.Stdin, os.Stdout, os.Stderr, trustKey, proto, addr, tlsConfig)

	if err := cli.Cmd(flag.Args()...); err != nil {
		if sterr, ok := err.(*utils.StatusError); ok {
			if sterr.Status != "" {
				log.Infof("%s", sterr.Status)
			}
			os.Exit(sterr.StatusCode)
		}
		log.Fatal(err)
	}
}

func showVersion() {
	fmt.Printf("Docker version %s, build %s\n", dockerversion.VERSION, dockerversion.GITCOMMIT)
}
