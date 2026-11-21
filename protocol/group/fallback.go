package group

import (
	"context"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

func RegisterFallback(registry *outbound.Registry) {
	outbound.Register[option.FallbackOutboundOptions](registry, C.TypeFallback, NewFallback)
}

var (
	_ adapter.OutboundGroup               = (*Fallback)(nil)
	_ adapter.OutboundWithConnectionState = (*Fallback)(nil)
	_ adapter.Referrer                    = (*Fallback)(nil)
)

type Fallback struct {
	outbound.Adapter
	outbound                     adapter.OutboundManager
	logger                       logger.ContextLogger
	tags                         []string
	timeout                      time.Duration
	interruptExternalConnections bool
	history                      *urltest.HistoryStorage
	pause                        pause.Manager
	pauseCallback                *list.Element[pause.Callback]
	members                      []*fallbackMember
	selected                     common.TypedValue[*fallbackMember]
	access                       sync.Mutex
	wanted                       int
	noneConnected                bool
	started                      bool
	closed                       bool
	paused                       bool
	pausedAt                     time.Time
	state                        adapter.ConnectionState
	stateUpdated                 chan struct{}
	timer                        *time.Timer
	notify                       chan struct{}
	done                         chan struct{}
	loopGroup                    sync.WaitGroup
}

type fallbackMember struct {
	index          int
	outbound       adapter.Outbound
	stateful       adapter.OutboundWithConnectionState
	interruptGroup *interrupt.Group
	state          adapter.ConnectionState
	release        func()
	waiting        bool
	waitDeadline   time.Time
}

func NewFallback(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FallbackOutboundOptions) (adapter.Outbound, error) {
	timeout := time.Duration(options.Timeout)
	if timeout < 0 {
		return nil, E.New("invalid timeout: ", timeout)
	}
	if timeout == 0 {
		timeout = C.DefaultFallbackTimeout
	}
	outbound := &Fallback{
		Adapter:                      outbound.NewAdapter(C.TypeFallback, tag, nil, options.Outbounds),
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		timeout:                      timeout,
		interruptExternalConnections: options.InterruptExistConnections,
		history:                      service.PtrFromContext[urltest.HistoryStorage](ctx),
		pause:                        service.FromContext[pause.Manager](ctx),
		stateUpdated:                 make(chan struct{}),
		notify:                       make(chan struct{}, 1),
		done:                         make(chan struct{}),
	}
	if len(outbound.tags) == 0 {
		return nil, E.New("missing tags")
	}
	for i, tag := range outbound.tags {
		if slices.Contains(outbound.tags[:i], tag) {
			return nil, E.New("duplicate tag: ", tag)
		}
	}
	return outbound, nil
}

func (g *Fallback) Network() []string {
	selected := g.selected.Load()
	if selected == nil {
		return []string{N.NetworkTCP, N.NetworkUDP}
	}
	return selected.outbound.Network()
}

func (g *Fallback) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateStart:
		for i, tag := range g.tags {
			detour, loaded := g.outbound.Outbound(tag)
			if !loaded {
				return E.New("outbound ", i, " not found: ", tag)
			}
			member := &fallbackMember{
				index:          i,
				outbound:       detour,
				interruptGroup: interrupt.NewGroup(),
			}
			member.stateful, _ = detour.(adapter.OutboundWithConnectionState)
			g.members = append(g.members, member)
		}
		g.selected.Store(g.members[0])
	case adapter.StartStateStarted:
		g.access.Lock()
		g.started = true
		g.timer = time.AfterFunc(g.timeout, g.notifyUpdate)
		if g.pause != nil {
			g.pauseCallback = g.pause.RegisterCallback(func(event int) {
				g.notifyUpdate()
			})
		}
		for _, member := range g.members {
			if member.stateful != nil {
				g.loopGroup.Add(1)
				go g.watchMember(member.stateful)
			}
		}
		g.loopGroup.Add(1)
		go g.loopUpdate()
		g.access.Unlock()
		g.notifyUpdate()
		scope.Add(g.Close)
	}
	return nil
}

func (g *Fallback) Close() error {
	g.access.Lock()
	if !g.started || g.closed {
		g.access.Unlock()
		return nil
	}
	g.closed = true
	close(g.done)
	g.timer.Stop()
	if g.pauseCallback != nil {
		g.pause.UnregisterCallback(g.pauseCallback)
		g.pauseCallback = nil
	}
	g.applyMonitoredLocked()
	g.access.Unlock()
	g.loopGroup.Wait()
	return nil
}

func (g *Fallback) All() []string {
	return g.tags
}

func (g *Fallback) Selected(network string) adapter.Outbound {
	selected := g.selected.Load()
	if selected == nil {
		return nil
	}
	return selected.outbound
}

func (g *Fallback) AttachConnection(closer io.Closer) func() {
	return g.selected.Load().interruptGroup.Add(closer, true)
}

func (g *Fallback) References() []string {
	g.access.Lock()
	defer g.access.Unlock()
	return g.tags[:g.wanted+1]
}

func (g *Fallback) ConnectionState() adapter.ConnectionState {
	g.access.Lock()
	defer g.access.Unlock()
	return g.state
}

func (g *Fallback) ConnectionStateUpdated() <-chan struct{} {
	g.access.Lock()
	defer g.access.Unlock()
	return g.stateUpdated
}

// Members are monitored by the group itself while they are wanted; when the group is not wanted by a parent, it is not referenced either, so on-demand members are suspended anyway.
func (g *Fallback) MonitorConnection() func() {
	return func() {}
}

func (g *Fallback) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	selected := g.selected.Load()
	conn, err := selected.outbound.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return selected.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

func (g *Fallback) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	selected := g.selected.Load()
	conn, err := selected.outbound.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return selected.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

func (g *Fallback) notifyUpdate() {
	select {
	case g.notify <- struct{}{}:
	default:
	}
}

func (g *Fallback) watchMember(member adapter.OutboundWithConnectionState) {
	defer g.loopGroup.Done()
	for {
		updated := member.ConnectionStateUpdated()
		g.notifyUpdate()
		select {
		case <-updated:
		case <-g.done:
			return
		}
	}
}

func (g *Fallback) loopUpdate() {
	defer g.loopGroup.Done()
	for {
		select {
		case <-g.notify:
		case <-g.done:
			return
		}
		g.update()
	}
}

func (g *Fallback) update() {
	g.access.Lock()
	if !g.started || g.closed {
		g.access.Unlock()
		return
	}
	now := time.Now()
	if g.pause != nil {
		paused := g.pause.IsDevicePaused() || g.pause.IsNetworkPaused()
		if paused && !g.paused {
			g.pausedAt = now
		}
		if !paused && g.paused {
			for _, member := range g.members[:g.wanted+1] {
				if member.state != adapter.ConnectionStateConnected {
					member.waiting = true
					member.waitDeadline = now.Add(g.timeout)
				}
			}
		}
		g.paused = paused
	}
	if g.paused {
		// Windows are measured on a clock frozen at the pause so that no member is given up while the device or network sleeps.
		now = g.pausedAt
	}
	previous := g.selected.Load()
	previousConnected := previous.state == adapter.ConnectionStateConnected
	allFailed := true
	for _, member := range g.members {
		state := adapter.ConnectionStateConnected
		if member.stateful != nil {
			state = member.stateful.ConnectionState()
		}
		if member.state == adapter.ConnectionStateConnected && state != adapter.ConnectionStateConnected && member.index <= g.wanted {
			member.waiting = true
			member.waitDeadline = now.Add(g.timeout)
		}
		member.state = state
		if state != adapter.ConnectionStateFailed {
			allFailed = false
		}
	}
	var connected, waiting *fallbackMember
	for _, member := range g.members {
		if member.state == adapter.ConnectionStateConnected {
			connected = member
			break
		}
		if member.state == adapter.ConnectionStateFailed {
			continue
		}
		if !member.waiting {
			member.waiting = true
			member.waitDeadline = now.Add(g.timeout)
		}
		if now.Before(member.waitDeadline) {
			waiting = member
			break
		}
	}
	selected := g.members[0]
	wanted := len(g.members) - 1
	switch {
	case connected != nil:
		selected = connected
		wanted = connected.index
	case waiting != nil:
		selected = waiting
		if previous.state == adapter.ConnectionStateConnected {
			selected = previous
		}
		wanted = max(selected.index, waiting.index)
	}
	for _, member := range g.members[wanted+1:] {
		member.waiting = false
	}
	referencesUpdated := wanted != g.wanted
	g.wanted = wanted
	g.applyMonitoredLocked()
	if selected != previous {
		g.selected.Store(selected)
		switch {
		case connected == nil && waiting == nil:
			g.logger.Info("no outbound connected, switching to ", selected.outbound.Tag())
		case selected == connected && selected.index < previous.index:
			g.logger.Info("outbound ", selected.outbound.Tag(), " connected, switching back from ", previous.outbound.Tag())
		case previous.state == adapter.ConnectionStateFailed && !g.noneConnected:
			g.logger.Info("outbound ", previous.outbound.Tag(), " failed, switching to ", selected.outbound.Tag())
		case previousConnected:
			g.logger.Info("outbound ", previous.outbound.Tag(), " lost connection, switching to ", selected.outbound.Tag())
		case !g.noneConnected && previous.waiting && !now.Before(previous.waitDeadline):
			g.logger.Info("outbound ", previous.outbound.Tag(), " not connected after ", g.timeout, ", falling back to ", selected.outbound.Tag())
		case selected == connected:
			g.logger.Info("outbound ", selected.outbound.Tag(), " connected, switching from ", previous.outbound.Tag())
		default:
			g.logger.Info("outbound ", previous.outbound.Tag(), " not connected, switching to ", selected.outbound.Tag())
		}
	}
	g.noneConnected = connected == nil && waiting == nil
	state := adapter.ConnectionStateDisconnected
	if selected.state == adapter.ConnectionStateConnected {
		state = adapter.ConnectionStateConnected
	} else if allFailed {
		state = adapter.ConnectionStateFailed
	}
	if state != g.state {
		g.state = state
		close(g.stateUpdated)
		g.stateUpdated = make(chan struct{})
	}
	if waiting != nil && !g.paused {
		g.timer.Reset(waiting.waitDeadline.Sub(now))
	} else {
		g.timer.Stop()
	}
	interruptExternal := g.interruptExternalConnections || previous.state != adapter.ConnectionStateConnected
	g.access.Unlock()
	if selected != previous {
		previous.interruptGroup.Interrupt(interruptExternal)
	}
	if (selected != previous || referencesUpdated) && g.history != nil {
		g.history.NotifyUpdated()
	}
}

func (g *Fallback) applyMonitoredLocked() {
	for _, member := range g.members {
		if member.stateful == nil {
			continue
		}
		monitored := !g.closed && member.index <= g.wanted
		if monitored && member.release == nil {
			member.release = member.stateful.MonitorConnection()
		} else if !monitored && member.release != nil {
			member.release()
			member.release = nil
		}
	}
}
