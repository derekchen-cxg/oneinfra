/**
 * Copyright 2020 Rafael Fernández López <ereslibre@ereslibre.es>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

package node

import (
	"bytes"
	"io/ioutil"
	"text/template"

	"github.com/oneinfra/oneinfra/internal/pkg/constants"
	"github.com/oneinfra/oneinfra/internal/pkg/infra"
	"github.com/oneinfra/oneinfra/internal/pkg/infra/pod"
	nodejoinrequests "github.com/oneinfra/oneinfra/internal/pkg/node-join-requests"
)

const (
	wireguardTemplate = `[Interface]
Address = {{ .Address }}
PrivateKey = {{ .PeerPrivateKey }}

[Peer]
Endpoint = {{ .Endpoint }}
PublicKey = {{ .EndpointPublicKey }}
AllowedIPs = {{ .CIDR }}
PersistentKeepalive = 21
`
)

func wireguardConfiguration(nodeJoinRequest *nodejoinrequests.NodeJoinRequest, symmetricKey string) (string, error) {
	template, err := template.New("").Parse(wireguardTemplate)
	if err != nil {
		return "", err
	}
	cidr, err := decrypt(symmetricKey, nodeJoinRequest.VPN.CIDR)
	if err != nil {
		return "", err
	}
	peerAddress, err := decrypt(symmetricKey, nodeJoinRequest.VPN.Address)
	if err != nil {
		return "", err
	}
	peerPrivateKey, err := decrypt(symmetricKey, nodeJoinRequest.VPN.PeerPrivateKey)
	if err != nil {
		return "", err
	}
	endpointAddress, err := decrypt(symmetricKey, nodeJoinRequest.VPN.Endpoint)
	if err != nil {
		return "", err
	}
	endpointPublicKey, err := decrypt(symmetricKey, nodeJoinRequest.VPN.EndpointPublicKey)
	if err != nil {
		return "", err
	}
	var rendered bytes.Buffer
	err = template.Execute(&rendered, nodejoinrequests.VPN{
		CIDR:              cidr,
		Address:           peerAddress,
		PeerPrivateKey:    peerPrivateKey,
		Endpoint:          endpointAddress,
		EndpointPublicKey: endpointPublicKey,
	})
	return rendered.String(), err
}

func setupWireguard(nodeJoinRequest *nodejoinrequests.NodeJoinRequest, symmetricKey string) error {
	hypervisor := infra.NewLocalHypervisor("wireguard-setup-image", nodeJoinRequest.ImageServiceEndpoint)
	if err := hypervisor.EnsureImage(constants.WireguardImage); err != nil {
		return err
	}
	wireguardConfig, err := wireguardConfiguration(nodeJoinRequest, symmetricKey)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(wireguardConfigPath, []byte(wireguardConfig), 0700); err != nil {
		return err
	}
	hypervisor = infra.NewLocalHypervisor("wireguard-setup-runtime", nodeJoinRequest.ContainerRuntimeEndpoint)
	// TODO: remove me
	hypervisor.EnsurePod(
		"",
		"",
		"wireguard-debug",
		pod.NewPod(
			"wireguard-debug",
			[]pod.Container{
				{
					Image:      constants.WireguardImage,
					Command:    []string{"sleep"},
					Args:       []string{"365d"},
					Privileges: pod.PrivilegesNetworkPrivileged,
					Mounts: map[string]string{
						"/etc/oneinfra": "/etc/oneinfra",
					},
				},
			},
			map[int]int{},
			pod.PrivilegesNetworkPrivileged,
		),
	)
	return hypervisor.RunAndWaitForPod(
		"",
		"",
		"wireguard",
		pod.NewPod(
			"wireguard",
			[]pod.Container{
				{
					Name:    "wireguard",
					Image:   constants.WireguardImage,
					Command: []string{"wg-quick"},
					Args: []string{
						"up",
						wireguardConfigPath,
					},
					Mounts: map[string]string{
						wireguardConfigPath: wireguardConfigPath,
					},
					Privileges: pod.PrivilegesNetworkPrivileged,
				},
			},
			map[int]int{},
			pod.PrivilegesNetworkPrivileged,
		),
	)
}
