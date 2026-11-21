package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/service/powerreport"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"

	"go4.org/netipx"
)

type Endpoint struct {
	options        EndpointOptions
	peers          []peerConfig
	ipcConf        string
	allowedAddress []netip.Prefix
	tunDevice      Device
	returnDevice   *returnDeviceWrapper
	device         atomic.Pointer[device.Device]
	allowedIPs     *device.AllowedIPs
	egressPool     *tun.UDPEgressPool
	pause          pause.Manager
	pauseCallback  *list.Element[pause.Callback]
	stateAccess    sync.Mutex
	suspended      atomic.Bool
	networkPaused  bool
	sessionAccess  sync.Mutex
	sessionStates  map[device.NoisePublicKey]device.PeerSessionState
	connected      bool
	sessionUpdated chan struct{}
	monitors       atomic.Int32
	monitorWake    chan struct{}
	monitorDone    chan struct{}
	monitorGroup   sync.WaitGroup
	revalidate     atomic.Bool
}

func NewEndpoint(options EndpointOptions) (*Endpoint, error) {
	if options.PrivateKey == "" {
		return nil, E.New("missing private key")
	}
	privateKeyBytes, err := base64.StdEncoding.DecodeString(options.PrivateKey)
	if err != nil {
		return nil, E.Cause(err, "decode private key")
	}
	privateKey := hex.EncodeToString(privateKeyBytes)
	ipcConf := "private_key=" + privateKey
	if options.ListenPort != 0 {
		ipcConf += "\nlisten_port=" + F.ToString(options.ListenPort)
	}
	var peers []peerConfig
	for peerIndex, rawPeer := range options.Peers {
		peer := peerConfig{
			allowedIPs: rawPeer.AllowedIPs,
			keepalive:  rawPeer.PersistentKeepaliveInterval,
		}
		if rawPeer.Endpoint.Addr.IsValid() {
			peer.endpoint = rawPeer.Endpoint.AddrPort()
		} else if rawPeer.Endpoint.IsDomain() {
			peer.destination = rawPeer.Endpoint
		}
		publicKeyBytes, err := base64.StdEncoding.DecodeString(rawPeer.PublicKey)
		if err != nil {
			return nil, E.Cause(err, "decode public key for peer ", peerIndex)
		}
		if len(publicKeyBytes) != device.NoisePublicKeySize {
			return nil, E.New("invalid public key for peer ", peerIndex, ", required ", device.NoisePublicKeySize, " bytes, got ", len(publicKeyBytes))
		}
		peer.publicKey = device.NoisePublicKey(publicKeyBytes)
		if rawPeer.PreSharedKey != "" {
			preSharedKeyBytes, err := base64.StdEncoding.DecodeString(rawPeer.PreSharedKey)
			if err != nil {
				return nil, E.Cause(err, "decode pre shared key for peer ", peerIndex)
			}
			peer.preSharedKeyHex = hex.EncodeToString(preSharedKeyBytes)
		}
		if len(rawPeer.AllowedIPs) == 0 {
			return nil, E.New("missing allowed ips for peer ", peerIndex)
		}
		if len(rawPeer.Reserved) > 0 {
			if len(rawPeer.Reserved) != 3 {
				return nil, E.New("invalid reserved value for peer ", peerIndex, ", required 3 bytes, got ", len(rawPeer.Reserved))
			}
			copy(peer.reserved[:], rawPeer.Reserved[:])
		}
		peers = append(peers, peer)
	}
	var allowedPrefixBuilder netipx.IPSetBuilder
	for _, peer := range options.Peers {
		for _, prefix := range peer.AllowedIPs {
			allowedPrefixBuilder.AddPrefix(prefix)
		}
	}
	allowedIPSet, err := allowedPrefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}
	allowedAddresses := allowedIPSet.Prefixes()
	if options.MTU == 0 {
		options.MTU = 1408
	}
	sessionStates := make(map[device.NoisePublicKey]device.PeerSessionState)
	for _, peer := range peers {
		if peer.endpoint.IsValid() || peer.destination.IsDomain() {
			sessionStates[peer.publicKey] = device.PeerSessionNone
		}
	}
	return &Endpoint{
		options:        options,
		peers:          peers,
		ipcConf:        ipcConf,
		allowedAddress: allowedAddresses,
		sessionStates:  sessionStates,
		connected:      len(sessionStates) == 0,
		sessionUpdated: make(chan struct{}),
		monitorWake:    make(chan struct{}, 1),
		monitorDone:    make(chan struct{}),
	}, nil
}

func (e *Endpoint) Initialize(memoryPressure func() tun.MemoryPressure) error {
	options := e.options
	deviceOptions := DeviceOptions{
		Context:         options.Context,
		Logger:          options.Logger,
		System:          options.System,
		Handler:         options.Handler,
		UDPTimeout:      options.UDPTimeout,
		ICMPTimeout:     options.ICMPTimeout,
		UDPMapping:      options.UDPMapping,
		UDPFiltering:    options.UDPFiltering,
		UDPNATMax:       options.UDPNATMax,
		InterfaceFinder: options.InterfaceFinder,
		MemoryPressure:  memoryPressure,
		CreateDialer:    options.CreateDialer,
		Name:            options.Name,
		MTU:             options.MTU,
		Address:         options.Address,
		AllowedAddress:  e.allowedAddress,
	}
	tunDevice, err := NewDevice(deviceOptions)
	if err != nil {
		return E.Cause(err, "create WireGuard device")
	}
	e.tunDevice = tunDevice
	e.returnDevice = &returnDeviceWrapper{Device: tunDevice}
	return nil
}

func (e *Endpoint) Start(postStart bool) error {
	hasDomainPeer := common.Any(e.peers, func(peer peerConfig) bool {
		return peer.destination.IsDomain()
	})
	if postStart != hasDomainPeer {
		return nil
	}
	var bind conn.Bind
	udpListener, isUDPListener := common.Cast[dialer.UDPListener](e.options.Dialer)
	if isUDPListener {
		listenerControl, egressEnabled := udpListener.UDPListenerControl()
		standardBind := conn.NewStdNetBind(listenerControl).(*conn.StdNetBind)
		if e.options.ListenPort == 0 && len(e.peers) == 1 && e.peers[0].endpoint.IsValid() {
			standardBind.SetSinglePeerMode()
		}
		if egressEnabled {
			egressPoolOptions := e.options.EgressPoolOptions
			egressPoolOptions.Control = listenerControl
			e.egressPool = tun.NewUDPEgressPool(egressPoolOptions)
			standardBind.SetEgressProvider(e.egressPool)
		}
		powerManager := service.FromContext[*powerreport.Manager](e.options.Context)
		if powerManager != nil {
			recorder := powerManager.Recorder()
			if recorder != nil {
				attribution := &powerreport.Attribution{Endpoint: e.options.Tag}
				counter := recorder.TrafficCounter(powerreport.TrafficEndpoint, e.options.Tag)
				standardBind.SetIOActivityFuncs(func(size int) {
					counter.CountIn(int64(size))
					recorder.Touch(powerreport.DirectionInbound, size, attribution)
				}, func(size int) {
					counter.CountOut(int64(size))
					recorder.Touch(powerreport.DirectionOutbound, size, attribution)
				})
			}
		}
		bind = standardBind
	} else {
		var (
			isConnect   bool
			connectAddr netip.AddrPort
			reserved    [3]uint8
		)
		if len(e.peers) == 1 {
			reserved = e.peers[0].reserved
			if e.peers[0].endpoint.IsValid() {
				isConnect = true
				connectAddr = e.peers[0].endpoint
			}
		}
		bind = NewClientBind(e.options.Context, e.options.Logger, e.options.Dialer, isConnect, connectAddr, reserved)
	}
	if isUDPListener || len(e.peers) > 1 {
		for _, peer := range e.peers {
			if peer.endpoint.IsValid() && peer.reserved != [3]uint8{} {
				bind.SetReservedForEndpoint(peer.endpoint, peer.reserved)
			}
		}
	}
	err := e.tunDevice.Start()
	if err != nil {
		return err
	}
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			e.options.Logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...any) {
			e.options.Logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	}
	wgDevice := device.NewDevice(e.options.Context, e.returnDevice, bind, logger, e.options.Workers)
	// Session states are not replayed, so the callback must be installed before IpcSet creates the peers.
	wgDevice.SetSessionStateFunc(e.onSessionState)
	domainPeers := make(map[device.NoisePublicKey]*peerConfig)
	for peerIndex, peer := range e.peers {
		if peer.destination.IsDomain() {
			domainPeers[peer.publicKey] = &e.peers[peerIndex]
		}
	}
	if len(domainPeers) > 0 {
		wgDevice.SetEndpointResolverFunc(func(publicKey device.NoisePublicKey) ([]conn.Endpoint, error) {
			peer, found := domainPeers[publicKey]
			if !found {
				return nil, nil
			}
			addresses, lookupErr := e.options.ResolvePeer(peer.destination.Fqdn)
			if lookupErr != nil {
				return nil, lookupErr
			}
			endpoints := make([]conn.Endpoint, 0, len(addresses))
			for _, address := range addresses {
				destination := netip.AddrPortFrom(address, peer.destination.Port)
				if peer.reserved != ([3]uint8{}) {
					bind.SetReservedForEndpoint(destination, peer.reserved)
				}
				endpoint, parseErr := bind.ParseEndpoint(destination.String())
				if parseErr != nil {
					return nil, parseErr
				}
				endpoints = append(endpoints, endpoint)
			}
			return endpoints, nil
		})
	}
	var ipcConf strings.Builder
	ipcConf.WriteString(e.ipcConf)
	for _, peer := range e.peers {
		ipcConf.WriteString(peer.GenerateIpcLines())
	}
	err = wgDevice.IpcSet(ipcConf.String())
	if err != nil {
		wgDevice.Close()
		return E.Cause(err, "setup wireguard: \n", ipcConf.String())
	}
	wgPeers := make([]*device.Peer, 0, len(e.peers))
	for _, peer := range e.peers {
		wgPeer, loaded := wgDevice.LookupActivePeer(peer.publicKey)
		if loaded {
			wgPeers = append(wgPeers, wgPeer)
		}
	}
	e.tunDevice.SetDevice(wgDevice, wgPeers)
	e.device.Store(wgDevice)
	e.pause = service.FromContext[pause.Manager](e.options.Context)
	if e.pause != nil {
		e.pauseCallback = e.pause.RegisterCallback(e.onPauseUpdated)
	}
	e.allowedIPs = wgDevice.AllowedIPs()
	e.monitorGroup.Add(1)
	go e.loopMonitor()
	return nil
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	e.resume()
	return e.tunDevice.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	e.resume()
	return e.tunDevice.ListenPacket(ctx, destination)
}

func (e *Endpoint) SetIdle(idle bool) {
	e.stateAccess.Lock()
	defer e.stateAccess.Unlock()
	wgDevice := e.device.Load()
	if wgDevice == nil {
		return
	}
	if idle {
		if e.suspended.Load() {
			return
		}
		e.suspended.Store(true)
		wgDevice.Down()
	} else {
		e.resumeLocked(wgDevice)
	}
}

func (e *Endpoint) resume() {
	if !e.suspended.Load() {
		return
	}
	e.stateAccess.Lock()
	defer e.stateAccess.Unlock()
	wgDevice := e.device.Load()
	if wgDevice == nil {
		return
	}
	e.resumeLocked(wgDevice)
}

func (e *Endpoint) resumeLocked(wgDevice *device.Device) {
	if !e.suspended.Load() {
		return
	}
	e.suspended.Store(false)
	if !e.networkPaused {
		wgDevice.Up()
		e.wakeMonitor()
	}
}

func (e *Endpoint) Close() error {
	e.stateAccess.Lock()
	select {
	case <-e.monitorDone:
	default:
		close(e.monitorDone)
	}
	e.stateAccess.Unlock()
	e.monitorGroup.Wait()
	if e.pauseCallback != nil {
		e.pause.UnregisterCallback(e.pauseCallback)
		e.pauseCallback = nil
	}
	if e.egressPool != nil {
		e.egressPool.Close()
		e.egressPool = nil
	}
	e.stateAccess.Lock()
	wgDevice := e.device.Swap(nil)
	if wgDevice != nil {
		wgDevice.Down()
		wgDevice.Close()
	}
	e.stateAccess.Unlock()
	if wgDevice != nil {
		return nil
	}
	return common.Close(e.tunDevice)
}

func (e *Endpoint) Lookup(address netip.Addr) *device.Peer {
	if e.allowedIPs == nil {
		return nil
	}
	return e.allowedIPs.LookupFromPacket(netip.Addr{}, address, nil)
}

func (e *Endpoint) BindUpdate() error {
	wgDevice := e.device.Load()
	if wgDevice == nil {
		return nil
	}
	err := wgDevice.BindUpdate()
	if err != nil {
		return err
	}
	// An established session survives a bind update although the new path may drop UDP, and a rekey of an established session does not change its observable state, so the monitor expires the keypairs to force a fresh handshake through the new socket as soon as the endpoint is monitored and active.
	e.revalidate.Store(true)
	e.wakeMonitor()
	return nil
}

func (e *Endpoint) Connected() bool {
	e.sessionAccess.Lock()
	defer e.sessionAccess.Unlock()
	return e.connected
}

func (e *Endpoint) ConnectedUpdated() <-chan struct{} {
	e.sessionAccess.Lock()
	defer e.sessionAccess.Unlock()
	return e.sessionUpdated
}

func (e *Endpoint) Monitor() func() {
	if e.monitors.Add(1) == 1 {
		e.wakeMonitor()
	}
	return sync.OnceFunc(func() {
		e.monitors.Add(-1)
	})
}

// Called by wireguard-go under the peer's session state lock: it must not call back into the device.
func (e *Endpoint) onSessionState(publicKey device.NoisePublicKey, state device.PeerSessionState) {
	e.sessionAccess.Lock()
	_, loaded := e.sessionStates[publicKey]
	if loaded {
		e.sessionStates[publicKey] = state
		connected := true
		for _, peerState := range e.sessionStates {
			if peerState != device.PeerSessionEstablished {
				connected = false
				break
			}
		}
		if connected != e.connected {
			e.connected = connected
			close(e.sessionUpdated)
			e.sessionUpdated = make(chan struct{})
		}
	}
	e.sessionAccess.Unlock()
	if loaded && (state == device.PeerSessionNone || state == device.PeerSessionExpired) {
		e.wakeMonitor()
	}
}

func (e *Endpoint) wakeMonitor() {
	select {
	case e.monitorWake <- struct{}{}:
	default:
	}
}

func (e *Endpoint) loopMonitor() {
	defer e.monitorGroup.Done()
	for {
		select {
		case <-e.monitorWake:
		case <-e.monitorDone:
			return
		}
		revalidate := e.revalidate.Load()
		if revalidate {
			// The expiry discards the handshake in flight, and a responder drops an initiation that arrives within 20ms of the previous one or carries the same timestamp (2^24ns granularity), so a forced handshake right after another initiation would stall until the next retransmission 5s later.
			select {
			case <-time.After(50 * time.Millisecond):
			case <-e.monitorDone:
				return
			}
		}
		if e.monitors.Load() == 0 {
			continue
		}
		activeDevice := e.activeDevice()
		if activeDevice == nil {
			continue
		}
		// A revalidation requested after the check above is left for the next wake, which waits before forcing the handshake.
		revalidate = revalidate && e.revalidate.Swap(false)
		for _, peer := range e.monitoredPeers(activeDevice, revalidate) {
			if revalidate {
				peer.ExpireCurrentKeypairs()
			}
			peer.SendHandshakeInitiation(false)
		}
	}
}

func (e *Endpoint) activeDevice() *device.Device {
	e.stateAccess.Lock()
	defer e.stateAccess.Unlock()
	if e.suspended.Load() || e.networkPaused || e.pause != nil && e.pause.IsDevicePaused() {
		return nil
	}
	return e.device.Load()
}

func (e *Endpoint) monitoredPeers(wgDevice *device.Device, all bool) []*device.Peer {
	e.sessionAccess.Lock()
	var publicKeys []device.NoisePublicKey
	for publicKey, state := range e.sessionStates {
		if all || state != device.PeerSessionEstablished {
			publicKeys = append(publicKeys, publicKey)
		}
	}
	e.sessionAccess.Unlock()
	var peers []*device.Peer
	for _, publicKey := range publicKeys {
		peer, loaded := wgDevice.LookupActivePeer(publicKey)
		if loaded {
			peers = append(peers, peer)
		}
	}
	return peers
}

func (e *Endpoint) onPauseUpdated(event int) {
	switch event {
	case pause.EventNetworkPause, pause.EventNetworkWake:
		go e.updateNetworkPause()
	case pause.EventDeviceWake:
		e.wakeMonitor()
	}
}

func (e *Endpoint) updateNetworkPause() {
	e.stateAccess.Lock()
	defer e.stateAccess.Unlock()
	wgDevice := e.device.Load()
	if wgDevice == nil {
		return
	}
	e.networkPaused = e.pause.IsNetworkPaused()
	if e.networkPaused {
		wgDevice.Down()
	} else if !e.suspended.Load() {
		wgDevice.Up()
		e.wakeMonitor()
	}
}

type peerConfig struct {
	destination     M.Socksaddr
	endpoint        netip.AddrPort
	publicKey       device.NoisePublicKey
	preSharedKeyHex string
	allowedIPs      []netip.Prefix
	keepalive       uint16
	reserved        [3]uint8
}

func (c peerConfig) GenerateIpcLines() string {
	var ipcLines strings.Builder
	ipcLines.WriteString("\npublic_key=" + hex.EncodeToString(c.publicKey[:]))
	if c.endpoint.IsValid() {
		ipcLines.WriteString("\nendpoint=" + c.endpoint.String())
	}
	if c.preSharedKeyHex != "" {
		ipcLines.WriteString("\npreshared_key=" + c.preSharedKeyHex)
	}
	for _, allowedIP := range c.allowedIPs {
		ipcLines.WriteString("\nallowed_ip=" + allowedIP.String())
	}
	if c.keepalive > 0 {
		ipcLines.WriteString("\npersistent_keepalive_interval=" + F.ToString(c.keepalive))
	}
	return ipcLines.String()
}
