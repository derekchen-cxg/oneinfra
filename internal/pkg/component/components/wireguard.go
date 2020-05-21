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

package components

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"net"
	"strconv"
	"text/template"

	"github.com/oneinfra/oneinfra/internal/pkg/constants"
	"github.com/oneinfra/oneinfra/internal/pkg/infra/pod"
	"github.com/oneinfra/oneinfra/internal/pkg/inquirer"
)

const (
	// WireguardHostPortName represents the wireguard host port
	// allocation name
	WireguardHostPortName = "wireguard"
)

const (
	wireguardQuickTemplate = `[Interface]
Address = {{ .Address }}
ListenPort = {{ .ListenPort }}
PrivateKey = {{ .PrivateKey }}
`

	wireguardTemplate = `[Interface]
ListenPort = {{ .ListenPort }}
PrivateKey = {{ .PrivateKey }}

{{- range $peer := .Peers }}
[Peer]
PublicKey = {{ $peer.PublicKey }}
AllowedIPs = {{ $peer.AllowedIPs }}
{{- end }}
`
)

func (ingress *ControlPlaneIngress) wireguardConfiguration(inquirer inquirer.ReconcilerInquirer) (string, string, error) {
	component := inquirer.Component()
	hypervisor := inquirer.Hypervisor()
	cluster := inquirer.Cluster()
	wireguardHostPort, err := component.RequestPort(hypervisor, WireguardHostPortName)
	if err != nil {
		return "", "", err
	}
	vpnPeer, err := cluster.VPNPeer("control-plane-ingress")
	if err != nil {
		return "", "", err
	}
	quickTemplate, err := template.New("").Parse(wireguardQuickTemplate)
	if err != nil {
		return "", "", err
	}
	template, err := template.New("").Parse(wireguardTemplate)
	if err != nil {
		return "", "", err
	}
	wireguardConfigData := struct {
		Address    string
		ListenPort string
		PrivateKey string
		Peers      []struct {
			PublicKey  string
			AllowedIPs string
		}
	}{
		Address:    vpnPeer.Address,
		ListenPort: strconv.Itoa(wireguardHostPort),
		PrivateKey: vpnPeer.PrivateKey,
		Peers: []struct {
			PublicKey  string
			AllowedIPs string
		}{},
	}
	for _, vpnPeer := range cluster.VPNPeers {
		if vpnPeer.Name == "control-plane-ingress" {
			continue
		}
		var ipAddressNet net.IPNet
		ipAddress, _, err := net.ParseCIDR(vpnPeer.Address)
		if err != nil {
			return "", "", err
		}
		if len(ipAddress) == net.IPv6len {
			ipAddressNet = net.IPNet{IP: ipAddress, Mask: net.CIDRMask(128, 128)}
		} else {
			ipAddressNet = net.IPNet{IP: ipAddress, Mask: net.CIDRMask(32, 32)}
		}
		wireguardConfigData.Peers = append(wireguardConfigData.Peers, struct {
			PublicKey  string
			AllowedIPs string
		}{
			PublicKey:  vpnPeer.PublicKey,
			AllowedIPs: ipAddressNet.String(),
		})
	}
	var quickRendered, rendered bytes.Buffer
	err = quickTemplate.Execute(&quickRendered, wireguardConfigData)
	if err != nil {
		return "", "", err
	}
	err = template.Execute(&rendered, wireguardConfigData)
	return quickRendered.String(), rendered.String(), err
}

func (ingress *ControlPlaneIngress) reconcileWireguard(inquirer inquirer.ReconcilerInquirer) error {
	component := inquirer.Component()
	hypervisor := inquirer.Hypervisor()
	cluster := inquirer.Cluster()
	if err := hypervisor.EnsureImage(constants.WireguardImage); err != nil {
		return err
	}
	wireguardQuickConfig, wireguardConfig, err := ingress.wireguardConfiguration(inquirer)
	if err != nil {
		return err
	}
	err = hypervisor.UploadFiles(
		cluster.Namespace,
		cluster.Name,
		component.Name,
		map[string]string{
			wireguardQuickConfigHostFile(cluster.Namespace, cluster.Name, component.Name): wireguardQuickConfig,
			wireguardConfigHostFile(cluster.Namespace, cluster.Name, component.Name):      wireguardConfig,
		},
	)
	if err != nil {
		return err
	}
	// TODO: remove me
	hypervisor.EnsurePod(
		"",
		"",
		"wireguard-debug-quick",
		pod.NewPod(
			"wireguard-debug-quick",
			[]pod.Container{
				{
					Name:       "wireguard-debug-quick",
					Image:      constants.WireguardImage,
					Command:    []string{"sleep"},
					Args:       []string{"365d"},
					Privileges: pod.PrivilegesNetworkPrivileged,
					Mounts: map[string]string{
						wireguardQuickConfigHostFile(cluster.Namespace, cluster.Name, component.Name): wireguardConfigGuestFile(cluster.Namespace, cluster.Name, component.Name),
					},
				},
			},
			map[int]int{},
			pod.PrivilegesNetworkPrivileged,
		),
	)
	hypervisor.EnsurePod(
		"",
		"",
		"wireguard-debug",
		pod.NewPod(
			"wireguard-debug",
			[]pod.Container{
				{
					Name:       "wireguard-debug",
					Image:      constants.WireguardImage,
					Command:    []string{"sleep"},
					Args:       []string{"365d"},
					Privileges: pod.PrivilegesNetworkPrivileged,
					Mounts: map[string]string{
						wireguardConfigHostFile(cluster.Namespace, cluster.Name, component.Name): wireguardConfigGuestFile(cluster.Namespace, cluster.Name, component.Name),
					},
				},
			},
			map[int]int{},
			pod.PrivilegesNetworkPrivileged,
		),
	)
	err = hypervisor.RunAndWaitForPod(
		cluster.Namespace,
		cluster.Name,
		component.Name,
		pod.NewPod(
			fmt.Sprintf("wireguard-%s", cluster.Name),
			[]pod.Container{
				{
					Name:    "wireguard",
					Image:   constants.WireguardImage,
					Command: []string{"wg-quick"},
					Args: []string{
						"up",
						wireguardConfigGuestFile(cluster.Namespace, cluster.Name, component.Name),
					},
					Mounts: map[string]string{
						wireguardQuickConfigHostFile(cluster.Namespace, cluster.Name, component.Name): wireguardConfigGuestFile(cluster.Namespace, cluster.Name, component.Name),
					},
					Privileges: pod.PrivilegesNetworkPrivileged,
				},
			},
			map[int]int{},
			pod.PrivilegesNetworkPrivileged,
		),
	)
	if err != nil {
		return err
	}
	return hypervisor.RunAndWaitForPod(
		cluster.Namespace,
		cluster.Name,
		component.Name,
		pod.NewPod(
			fmt.Sprintf("wireguard-%s", cluster.Name),
			[]pod.Container{
				{
					Name:    "wireguard",
					Image:   constants.WireguardImage,
					Command: []string{"wg"},
					Args: []string{
						"syncconf",
						wireguardInterfaceName(cluster.Namespace, cluster.Name),
						wireguardConfigGuestFile(cluster.Namespace, cluster.Name, component.Name),
					},
					Mounts: map[string]string{
						wireguardConfigHostFile(cluster.Namespace, cluster.Name, component.Name): wireguardConfigGuestFile(cluster.Namespace, cluster.Name, component.Name),
					},
					Privileges: pod.PrivilegesNetworkPrivileged,
				},
			},
			map[int]int{},
			pod.PrivilegesNetworkPrivileged,
		),
	)
}

func wireguardQuickConfigHostFile(clusterNamespace, clusterName, componentName string) string {
	return componentSecretsPathFile(clusterNamespace, clusterName, componentName, "wg-quick.conf")
}

func wireguardConfigHostFile(clusterNamespace, clusterName, componentName string) string {
	return componentSecretsPathFile(clusterNamespace, clusterName, componentName, "wg.conf")
}

func wireguardConfigGuestFile(clusterNamespace, clusterName, componentName string) string {
	return componentSecretsPathFile(clusterNamespace, clusterName, componentName, fmt.Sprintf("%s.conf", wireguardInterfaceName(clusterNamespace, clusterName)))
}

func wireguardInterfaceName(clusterNamespace, clusterName string) string {
	return fmt.Sprintf("wg-%x", sha1.Sum([]byte(fmt.Sprintf("%s-%s", clusterNamespace, clusterName))))[0:15]
}
