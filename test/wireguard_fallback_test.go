//go:build with_wireguard

package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

type wireGuardRelay struct {
	listener    *net.UDPConn
	upstream    *net.UDPConn
	client      atomic.Pointer[net.UDPAddr]
	drop        atomic.Bool
	initiations atomic.Int32
}

func newWireGuardRelay(t *testing.T, serverPort uint16) *wireGuardRelay {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	upstream, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(serverPort)})
	require.NoError(t, err)
	relay := &wireGuardRelay{listener: listener, upstream: upstream}
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, source, readErr := listener.ReadFromUDP(buffer)
			if readErr != nil {
				if errors.Is(readErr, net.ErrClosed) {
					return
				}
				continue
			}
			if n == 148 && buffer[0] == 1 {
				relay.initiations.Add(1)
			}
			if relay.drop.Load() {
				continue
			}
			relay.client.Store(source)
			upstream.Write(buffer[:n])
		}
	}()
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, readErr := upstream.Read(buffer)
			if readErr != nil {
				if errors.Is(readErr, net.ErrClosed) {
					return
				}
				continue
			}
			client := relay.client.Load()
			if relay.drop.Load() || client == nil {
				continue
			}
			listener.WriteToUDP(buffer[:n], client)
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		upstream.Close()
	})
	return relay
}

func (r *wireGuardRelay) Port() uint16 {
	return uint16(r.listener.LocalAddr().(*net.UDPAddr).Port)
}

type wireGuardTestKeys struct {
	server        string
	serverPublic  string
	client        string
	clientPublic  string
	serverPort    uint16
	serverAddress netip.Prefix
	clientAddress netip.Prefix
}

func newWireGuardTestKeys(t *testing.T) wireGuardTestKeys {
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	portReservation, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	serverPort := uint16(portReservation.LocalAddr().(*net.UDPAddr).Port)
	require.NoError(t, portReservation.Close())
	return wireGuardTestKeys{
		server:        base64.StdEncoding.EncodeToString(serverKey.Bytes()),
		serverPublic:  base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()),
		client:        base64.StdEncoding.EncodeToString(clientKey.Bytes()),
		clientPublic:  base64.StdEncoding.EncodeToString(clientKey.PublicKey().Bytes()),
		serverPort:    serverPort,
		serverAddress: netip.MustParsePrefix("198.18.19.1/32"),
		clientAddress: netip.MustParsePrefix("198.18.19.2/32"),
	}
}

func (k wireGuardTestKeys) serverEndpoint() option.Endpoint {
	return option.Endpoint{
		Type: C.TypeWireGuard,
		Tag:  "server",
		Options: &option.WireGuardEndpointOptions{
			MTU: 1280, Address: []netip.Prefix{k.serverAddress}, Workers: 2,
			PrivateKey: k.server,
			ListenPort: k.serverPort,
			Peers: []option.WireGuardPeer{{
				PublicKey:  k.clientPublic,
				AllowedIPs: []netip.Prefix{k.clientAddress},
			}},
		},
	}
}

func (k wireGuardTestKeys) clientEndpoint(relayPort uint16, detour string) option.Endpoint {
	return option.Endpoint{
		Type: C.TypeWireGuard,
		Tag:  "client",
		Options: &option.WireGuardEndpointOptions{
			MTU: 1280, Address: []netip.Prefix{k.clientAddress}, Workers: 2,
			PrivateKey: k.client,
			Peers: []option.WireGuardPeer{{
				Address: "127.0.0.1", Port: relayPort,
				PublicKey:  k.serverPublic,
				AllowedIPs: []netip.Prefix{k.serverAddress},
			}},
			DialerOptions: option.DialerOptions{Detour: detour},
		},
	}
}

func requireConnectionStateEventually(t *testing.T, outbound adapter.OutboundWithConnectionState, expected adapter.ConnectionState, timeout time.Duration) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		updated := outbound.ConnectionStateUpdated()
		if outbound.ConnectionState() == expected {
			return
		}
		select {
		case <-updated:
		case <-deadline.C:
			t.Fatalf("connection state %d not reached after %s", expected, timeout)
		}
	}
}

func requireNotConnectedFor(t *testing.T, outbound adapter.OutboundWithConnectionState, duration time.Duration) {
	t.Helper()
	deadline := time.NewTimer(duration)
	defer deadline.Stop()
	for {
		updated := outbound.ConnectionStateUpdated()
		require.NotEqual(t, adapter.ConnectionStateConnected, outbound.ConnectionState())
		select {
		case <-updated:
		case <-deadline.C:
			return
		}
	}
}

func clientConnectionState(t *testing.T, instance *box.Box) adapter.OutboundWithConnectionState {
	endpoint, loaded := instance.Endpoint().Get("client")
	require.True(t, loaded)
	return endpoint.(adapter.OutboundWithConnectionState)
}

func TestWireGuardConnectionState(t *testing.T) {
	for _, detour := range []string{"", "detour"} {
		t.Run("detour="+detour, func(t *testing.T) {
			keys := newWireGuardTestKeys(t)
			relay := newWireGuardRelay(t, keys.serverPort)
			instance := startInstance(t, option.Options{
				Endpoints: []option.Endpoint{keys.serverEndpoint(), keys.clientEndpoint(relay.Port(), detour)},
				Outbounds: []option.Outbound{
					{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}},
					{Type: C.TypeDirect, Tag: "detour", Options: &option.DirectOutboundOptions{
						DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{ConnectTimeout: badoption.Duration(5 * time.Second)}},
					}},
				},
				Route: &option.RouteOptions{Final: "direct"},
			})
			client := clientConnectionState(t, instance)
			interfaceUpdated := func() {
				client.(adapter.InterfaceUpdateListener).InterfaceUpdated(context.Background())
			}

			time.Sleep(time.Second)
			interfaceUpdated()
			time.Sleep(500 * time.Millisecond)
			require.Zero(t, relay.initiations.Load(), "an unmonitored idle endpoint must not initiate handshakes")
			require.Equal(t, adapter.ConnectionStateDisconnected, client.ConnectionState())

			release := client.MonitorConnection()
			requireConnectionStateEventually(t, client, adapter.ConnectionStateConnected, 3*time.Second)

			initiations := relay.initiations.Load()
			interfaceUpdated()
			require.Eventually(t, func() bool {
				return relay.initiations.Load() > initiations
			}, 2*time.Second, 10*time.Millisecond, "a network change must force a fresh handshake")
			requireConnectionStateEventually(t, client, adapter.ConnectionStateConnected, 3*time.Second)

			relay.drop.Store(true)
			interfaceUpdated()
			requireConnectionStateEventually(t, client, adapter.ConnectionStateDisconnected, 2*time.Second)
			requireNotConnectedFor(t, client, 6*time.Second)

			relay.drop.Store(false)
			requireConnectionStateEventually(t, client, adapter.ConnectionStateConnected, 8*time.Second)

			keeper := client.(adapter.OnDemandEndpoint)
			keeper.SetKeepIdleConnections(false)
			requireConnectionStateEventually(t, client, adapter.ConnectionStateDisconnected, 2*time.Second)
			initiations = relay.initiations.Load()
			time.Sleep(time.Second)
			require.Equal(t, initiations, relay.initiations.Load(), "a suspended endpoint must not initiate handshakes")
			keeper.SetKeepIdleConnections(true)
			requireConnectionStateEventually(t, client, adapter.ConnectionStateConnected, 3*time.Second)

			release()
			initiations = relay.initiations.Load()
			interfaceUpdated()
			time.Sleep(time.Second)
			require.Equal(t, initiations, relay.initiations.Load(), "an unmonitored endpoint must not revalidate after a network change")
			require.Equal(t, adapter.ConnectionStateConnected, client.ConnectionState())

			keeper.SetKeepIdleConnections(false)
			keeper.SetKeepIdleConnections(true)
			time.Sleep(time.Second)
			require.Equal(t, initiations, relay.initiations.Load(), "an unmonitored endpoint must not initiate handshakes after a resume")
			require.Equal(t, adapter.ConnectionStateDisconnected, client.ConnectionState())
		})
	}
}

func TestWireGuardRevalidation(t *testing.T) {
	keys := newWireGuardTestKeys(t)
	relay := newWireGuardRelay(t, keys.serverPort)
	startInstance(t, option.Options{
		Endpoints: []option.Endpoint{keys.serverEndpoint()},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}}},
		Route:     &option.RouteOptions{Final: "direct"},
	})
	// Boxes created from globalCtx share one service registry and therefore one pause manager, so the client gets its own to be paused alone.
	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: option.Options{
			Log:       &option.LogOptions{Level: "warning"},
			Endpoints: []option.Endpoint{keys.clientEndpoint(relay.Port(), "")},
			Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}}},
			Route:     &option.RouteOptions{Final: "direct"},
		},
	})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() {
		instance.Close()
		cancel()
	})
	pauseManager := service.FromContext[pause.Manager](ctx)
	client := clientConnectionState(t, instance)
	interfaceUpdated := func() {
		client.(adapter.InterfaceUpdateListener).InterfaceUpdated(context.Background())
	}

	release := client.MonitorConnection()
	requireConnectionStateEventually(t, client, adapter.ConnectionStateConnected, 3*time.Second)
	for range 3 {
		initiations := relay.initiations.Load()
		interfaceUpdated()
		interfaceUpdated()
		time.Sleep(100 * time.Millisecond)
		require.Greater(t, relay.initiations.Load(), initiations)
		requireConnectionStateEventually(t, client, adapter.ConnectionStateConnected, 2*time.Second)
	}

	release()
	relay.drop.Store(true)
	interfaceUpdated()
	time.Sleep(500 * time.Millisecond)
	require.Equal(t, adapter.ConnectionStateConnected, client.ConnectionState())
	release = client.MonitorConnection()
	requireConnectionStateEventually(t, client, adapter.ConnectionStateDisconnected, 2*time.Second)
	relay.drop.Store(false)
	interfaceUpdated()
	requireConnectionStateEventually(t, client, adapter.ConnectionStateConnected, 3*time.Second)

	pauseManager.DevicePause()
	relay.drop.Store(true)
	initiations := relay.initiations.Load()
	interfaceUpdated()
	time.Sleep(500 * time.Millisecond)
	require.Equal(t, initiations, relay.initiations.Load(), "a paused endpoint must not initiate handshakes")
	pauseManager.DeviceWake()
	requireConnectionStateEventually(t, client, adapter.ConnectionStateDisconnected, 2*time.Second)
	relay.drop.Store(false)
	interfaceUpdated()
	requireConnectionStateEventually(t, client, adapter.ConnectionStateConnected, 3*time.Second)
	release()
}

func TestFallbackWireGuard(t *testing.T) {
	keys := newWireGuardTestKeys(t)
	relay := newWireGuardRelay(t, keys.serverPort)
	relay.drop.Store(true)
	startInstance(t, option.Options{
		Endpoints: []option.Endpoint{keys.serverEndpoint()},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}}},
		Route:     &option.RouteOptions{Final: "direct"},
	})
	echoListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer echoListener.Close()
	go func() {
		for {
			conn, acceptErr := echoListener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	echoPort := uint16(echoListener.Addr().(*net.TCPAddr).Port)
	portReservation, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	inboundPort := uint16(portReservation.Addr().(*net.TCPAddr).Port)
	require.NoError(t, portReservation.Close())
	instance := startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: C.TypeMixed,
			Options: &option.HTTPMixedInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
					ListenPort: inboundPort,
				},
			},
		}},
		Endpoints: []option.Endpoint{keys.clientEndpoint(relay.Port(), "")},
		Outbounds: []option.Outbound{
			{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}},
			{Type: C.TypeFallback, Tag: "fallback", Options: &option.FallbackOutboundOptions{
				Outbounds: []string{"client", "direct"},
				Timeout:   badoption.Duration(time.Second),
			}},
		},
		Route: &option.RouteOptions{Final: "fallback"},
	})
	outbound, loaded := instance.Outbound().Outbound("fallback")
	require.True(t, loaded)
	group := outbound.(adapter.OutboundGroup)
	require.Equal(t, "client", group.Selected(N.NetworkTCP).Tag())
	require.Eventually(t, func() bool {
		return group.Selected(N.NetworkTCP).Tag() == "direct"
	}, 3*time.Second, 10*time.Millisecond)
	require.NotZero(t, relay.initiations.Load())
	client := clientConnectionState(t, instance)
	require.Equal(t, adapter.ConnectionStateDisconnected, client.ConnectionState())

	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", inboundPort), socks.Version5, "", "")
	requireEcho := func(destination M.Socksaddr) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, dialErr := dialer.DialContext(ctx, N.NetworkTCP, destination)
		require.NoError(t, dialErr)
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		payload := []byte("fallback")
		_, writeErr := conn.Write(payload)
		require.NoError(t, writeErr)
		received := make([]byte, len(payload))
		_, readErr := io.ReadFull(conn, received)
		require.NoError(t, readErr)
		require.Equal(t, payload, received)
	}
	requireEcho(M.ParseSocksaddrHostPort("127.0.0.1", echoPort))

	relay.drop.Store(false)
	require.Eventually(t, func() bool {
		return group.Selected(N.NetworkTCP).Tag() == "client"
	}, 8*time.Second, 10*time.Millisecond)
	requireEcho(M.SocksaddrFrom(keys.serverAddress.Addr(), echoPort))
}
