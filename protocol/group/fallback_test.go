package group

import (
	"context"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

type fallbackTestOutbound struct {
	tag string
}

func (o *fallbackTestOutbound) Type() string {
	return "test"
}

func (o *fallbackTestOutbound) Tag() string {
	return o.tag
}

func (o *fallbackTestOutbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (o *fallbackTestOutbound) Dependencies() []string {
	return nil
}

func (o *fallbackTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return &fallbackTestConn{}, nil
}

func (o *fallbackTestOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

type fallbackTestMember struct {
	fallbackTestOutbound
	access   sync.Mutex
	state    adapter.ConnectionState
	updated  chan struct{}
	monitors int
}

func newFallbackTestMember(tag string, state adapter.ConnectionState) *fallbackTestMember {
	return &fallbackTestMember{
		fallbackTestOutbound: fallbackTestOutbound{tag: tag},
		state:                state,
		updated:              make(chan struct{}),
	}
}

func (m *fallbackTestMember) ConnectionState() adapter.ConnectionState {
	m.access.Lock()
	defer m.access.Unlock()
	return m.state
}

func (m *fallbackTestMember) ConnectionStateUpdated() <-chan struct{} {
	m.access.Lock()
	defer m.access.Unlock()
	return m.updated
}

func (m *fallbackTestMember) MonitorConnection() func() {
	m.access.Lock()
	defer m.access.Unlock()
	m.monitors++
	return sync.OnceFunc(func() {
		m.access.Lock()
		defer m.access.Unlock()
		m.monitors--
	})
}

func (m *fallbackTestMember) Monitored() bool {
	m.access.Lock()
	defer m.access.Unlock()
	return m.monitors > 0
}

func (m *fallbackTestMember) SetState(state adapter.ConnectionState) {
	m.access.Lock()
	m.state = state
	close(m.updated)
	m.updated = make(chan struct{})
	m.access.Unlock()
	synctest.Wait()
}

type fallbackTestConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *fallbackTestConn) Close() error {
	c.closed.Store(true)
	return nil
}

type fallbackTestLogger struct {
	log.ContextLogger
	access   sync.Mutex
	messages []string
}

func (l *fallbackTestLogger) Info(args ...any) {
	l.access.Lock()
	defer l.access.Unlock()
	l.messages = append(l.messages, F.ToString(args...))
}

func (l *fallbackTestLogger) Messages() []string {
	l.access.Lock()
	defer l.access.Unlock()
	messages := l.messages
	l.messages = nil
	return messages
}

type fallbackTestManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m *fallbackTestManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}

type fallbackTestContext struct {
	ctx     context.Context
	manager *fallbackTestManager
	pause   pause.Manager
	updates *observable.Subscriber[struct{}]
	logger  *fallbackTestLogger
}

func newFallbackTestContext(outbounds ...adapter.Outbound) *fallbackTestContext {
	manager := &fallbackTestManager{outbounds: make(map[string]adapter.Outbound)}
	for _, outbound := range outbounds {
		manager.outbounds[outbound.Tag()] = outbound
	}
	history := urltest.NewHistoryStorage()
	updates := observable.NewSubscriber[struct{}](1)
	history.AddUpdateHook(updates)
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
	ctx = service.ContextWithPtr(ctx, history)
	ctx = pause.WithDefaultManager(ctx)
	return &fallbackTestContext{
		ctx:     ctx,
		manager: manager,
		pause:   service.FromContext[pause.Manager](ctx),
		updates: updates,
		logger:  &fallbackTestLogger{ContextLogger: log.NewNOPFactory().Logger()},
	}
}

func (c *fallbackTestContext) start(t *testing.T, tag string, options option.FallbackOutboundOptions) *Fallback {
	group := c.create(t, tag, options)
	synctest.Wait()
	return group
}

func (c *fallbackTestContext) create(t *testing.T, tag string, options option.FallbackOutboundOptions) *Fallback {
	outbound, err := NewFallback(c.ctx, nil, c.logger, tag, options)
	require.NoError(t, err)
	group := outbound.(*Fallback)
	c.manager.outbounds[tag] = group
	scope := adapter.NewScope(c.ctx, log.NewNOPFactory().Logger())
	require.NoError(t, group.Start(adapter.StartStateStart, scope))
	require.NoError(t, group.Start(adapter.StartStateStarted, scope))
	return group
}

func (c *fallbackTestContext) referencesNotified() bool {
	subscription, _ := c.updates.Subscription()
	select {
	case <-subscription:
		return true
	default:
		return false
	}
}

func requireSelected(t *testing.T, group adapter.OutboundGroup, tag string) {
	t.Helper()
	require.Equal(t, tag, group.Selected(N.NetworkTCP).Tag())
}

func sleep(duration time.Duration) {
	time.Sleep(duration)
	synctest.Wait()
}

func TestFallbackWaitsForFirstMember(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := newFallbackTestMember("first", adapter.ConnectionStateDisconnected)
		second := newFallbackTestMember("second", adapter.ConnectionStateConnected)
		testContext := newFallbackTestContext(first, second)
		group := testContext.start(t, "fallback", option.FallbackOutboundOptions{Outbounds: []string{"first", "second"}})
		defer group.Close()
		requireSelected(t, group, "first")
		require.Equal(t, []string{"first"}, group.References())
		require.True(t, first.Monitored())
		require.False(t, second.Monitored())
		require.Equal(t, adapter.ConnectionStateDisconnected, group.ConnectionState())
		sleep(C.DefaultFallbackTimeout - time.Millisecond)
		requireSelected(t, group, "first")
		first.SetState(adapter.ConnectionStateConnected)
		requireSelected(t, group, "first")
		require.Equal(t, adapter.ConnectionStateConnected, group.ConnectionState())
		sleep(time.Minute)
		requireSelected(t, group, "first")
		require.Equal(t, []string{"first"}, group.References())
		require.False(t, second.Monitored())
	})
}

func TestFallbackTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := newFallbackTestMember("first", adapter.ConnectionStateDisconnected)
		second := newFallbackTestMember("second", adapter.ConnectionStateConnected)
		testContext := newFallbackTestContext(first, second)
		group := testContext.start(t, "fallback", option.FallbackOutboundOptions{
			Outbounds: []string{"first", "second"},
			Timeout:   badoption.Duration(2 * time.Second),
		})
		defer group.Close()
		testContext.referencesNotified()
		sleep(time.Second)
		first.SetState(adapter.ConnectionStateDisconnected)
		sleep(time.Second - time.Millisecond)
		requireSelected(t, group, "first")
		require.False(t, testContext.referencesNotified())
		sleep(time.Millisecond)
		requireSelected(t, group, "second")
		require.Equal(t, []string{"first", "second"}, group.References())
		require.True(t, testContext.referencesNotified())
		require.True(t, first.Monitored())
		require.True(t, second.Monitored())
		require.Equal(t, adapter.ConnectionStateConnected, group.ConnectionState())
	})
}

func TestFallbackSwitchBack(t *testing.T) {
	for _, interruptExternal := range []bool{false, true} {
		t.Run(map[bool]string{false: "keep-external", true: "interrupt-external"}[interruptExternal], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				first := newFallbackTestMember("first", adapter.ConnectionStateDisconnected)
				second := newFallbackTestMember("second", adapter.ConnectionStateConnected)
				testContext := newFallbackTestContext(first, second)
				group := testContext.start(t, "fallback", option.FallbackOutboundOptions{
					Outbounds:                 []string{"first", "second"},
					InterruptExistConnections: interruptExternal,
				})
				defer group.Close()
				sleep(C.DefaultFallbackTimeout)
				requireSelected(t, group, "second")
				external := dialFallback(t, group, true)
				internal := dialFallback(t, group, false)
				attached := &fallbackTestConn{}
				group.AttachConnection(attached)
				testContext.referencesNotified()
				first.SetState(adapter.ConnectionStateConnected)
				requireSelected(t, group, "first")
				require.Equal(t, []string{"first"}, group.References())
				require.True(t, testContext.referencesNotified())
				require.False(t, second.Monitored())
				require.True(t, internal.closed.Load())
				require.Equal(t, interruptExternal, external.closed.Load())
				require.Equal(t, interruptExternal, attached.closed.Load())
			})
		})
	}
}

func TestFallbackConnectionLost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := newFallbackTestMember("first", adapter.ConnectionStateConnected)
		second := newFallbackTestMember("second", adapter.ConnectionStateConnected)
		testContext := newFallbackTestContext(first, second)
		group := testContext.start(t, "fallback", option.FallbackOutboundOptions{Outbounds: []string{"first", "second"}})
		defer group.Close()
		requireSelected(t, group, "first")
		external := dialFallback(t, group, true)
		internal := dialFallback(t, group, false)
		attached := &fallbackTestConn{}
		group.AttachConnection(attached)
		first.SetState(adapter.ConnectionStateDisconnected)
		sleep(C.DefaultFallbackTimeout - time.Millisecond)
		requireSelected(t, group, "first")
		require.False(t, second.Monitored())
		require.False(t, external.closed.Load())
		first.SetState(adapter.ConnectionStateConnected)
		first.SetState(adapter.ConnectionStateDisconnected)
		sleep(C.DefaultFallbackTimeout - time.Millisecond)
		requireSelected(t, group, "first")
		sleep(time.Millisecond)
		requireSelected(t, group, "second")
		require.True(t, external.closed.Load())
		require.True(t, internal.closed.Load())
		require.True(t, attached.closed.Load())
		require.True(t, first.Monitored())
		require.True(t, second.Monitored())
	})
}

func TestFallbackFailedSkipsWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := newFallbackTestMember("first", adapter.ConnectionStateDisconnected)
		second := newFallbackTestMember("second", adapter.ConnectionStateConnected)
		testContext := newFallbackTestContext(first, second)
		group := testContext.start(t, "fallback", option.FallbackOutboundOptions{Outbounds: []string{"first", "second"}})
		defer group.Close()
		connection := dialFallback(t, group, true)
		first.SetState(adapter.ConnectionStateFailed)
		requireSelected(t, group, "second")
		require.True(t, connection.closed.Load())
		require.Equal(t, []string{"first", "second"}, group.References())
	})
}

func TestFallbackWindowReset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := newFallbackTestMember("first", adapter.ConnectionStateConnected)
		second := newFallbackTestMember("second", adapter.ConnectionStateDisconnected)
		direct := &fallbackTestOutbound{tag: "direct"}
		testContext := newFallbackTestContext(first, second, direct)
		group := testContext.start(t, "fallback", option.FallbackOutboundOptions{Outbounds: []string{"first", "second", "direct"}})
		defer group.Close()
		first.SetState(adapter.ConnectionStateDisconnected)
		sleep(2 * C.DefaultFallbackTimeout)
		requireSelected(t, group, "direct")
		first.SetState(adapter.ConnectionStateConnected)
		requireSelected(t, group, "first")
		require.False(t, second.Monitored())
		first.SetState(adapter.ConnectionStateDisconnected)
		sleep(C.DefaultFallbackTimeout)
		requireSelected(t, group, "second")
		sleep(C.DefaultFallbackTimeout - time.Millisecond)
		requireSelected(t, group, "second")
		sleep(time.Millisecond)
		requireSelected(t, group, "direct")
	})
}

func TestFallbackStatelessMember(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := newFallbackTestMember("first", adapter.ConnectionStateDisconnected)
		direct := &fallbackTestOutbound{tag: "direct"}
		testContext := newFallbackTestContext(first, direct)
		group := testContext.start(t, "fallback", option.FallbackOutboundOptions{Outbounds: []string{"first", "direct"}})
		defer group.Close()
		requireSelected(t, group, "first")
		sleep(C.DefaultFallbackTimeout)
		requireSelected(t, group, "direct")
		require.Equal(t, adapter.ConnectionStateConnected, group.ConnectionState())
		first.SetState(adapter.ConnectionStateConnected)
		requireSelected(t, group, "first")
	})
}

func TestFallbackNoneConnected(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := newFallbackTestMember("first", adapter.ConnectionStateDisconnected)
		second := newFallbackTestMember("second", adapter.ConnectionStateDisconnected)
		testContext := newFallbackTestContext(first, second)
		group := testContext.start(t, "fallback", option.FallbackOutboundOptions{Outbounds: []string{"first", "second"}})
		defer group.Close()
		sleep(C.DefaultFallbackTimeout)
		requireSelected(t, group, "second")
		require.Equal(t, []string{"first", "second"}, group.References())
		sleep(C.DefaultFallbackTimeout)
		requireSelected(t, group, "first")
		require.Equal(t, []string{"first", "second"}, group.References())
		require.True(t, first.Monitored())
		require.True(t, second.Monitored())
		require.Equal(t, adapter.ConnectionStateDisconnected, group.ConnectionState())
		second.SetState(adapter.ConnectionStateConnected)
		requireSelected(t, group, "second")
		require.Equal(t, adapter.ConnectionStateConnected, group.ConnectionState())
		first.SetState(adapter.ConnectionStateFailed)
		second.SetState(adapter.ConnectionStateFailed)
		require.Equal(t, adapter.ConnectionStateFailed, group.ConnectionState())
	})
}

func TestFallbackPause(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := newFallbackTestMember("first", adapter.ConnectionStateDisconnected)
		second := newFallbackTestMember("second", adapter.ConnectionStateConnected)
		testContext := newFallbackTestContext(first, second)
		group := testContext.start(t, "fallback", option.FallbackOutboundOptions{Outbounds: []string{"first", "second"}})
		defer group.Close()
		sleep(time.Second)
		testContext.pause.DevicePause()
		sleep(time.Hour)
		second.SetState(adapter.ConnectionStateConnected)
		requireSelected(t, group, "first")
		testContext.pause.DeviceWake()
		sleep(C.DefaultFallbackTimeout - time.Millisecond)
		requireSelected(t, group, "first")
		sleep(time.Millisecond)
		requireSelected(t, group, "second")
		testContext.pause.NetworkPause()
		first.SetState(adapter.ConnectionStateConnected)
		requireSelected(t, group, "first")
		first.SetState(adapter.ConnectionStateDisconnected)
		sleep(time.Hour)
		second.SetState(adapter.ConnectionStateConnected)
		requireSelected(t, group, "first")
		testContext.pause.NetworkWake()
		sleep(C.DefaultFallbackTimeout)
		requireSelected(t, group, "second")
		testContext.pause.DevicePause()
		sleep(time.Minute)
		testContext.pause.DeviceWake()
		sleep(time.Second)
		requireSelected(t, group, "second")
		require.Equal(t, []string{"first", "second"}, group.References())
	})
}

func TestFallbackLogReason(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := newFallbackTestMember("first", adapter.ConnectionStateDisconnected)
		second := newFallbackTestMember("second", adapter.ConnectionStateDisconnected)
		testContext := newFallbackTestContext(first, second)
		group := testContext.start(t, "fallback", option.FallbackOutboundOptions{Outbounds: []string{"first", "second"}})
		defer group.Close()
		sleep(C.DefaultFallbackTimeout)
		sleep(C.DefaultFallbackTimeout)
		second.SetState(adapter.ConnectionStateConnected)
		first.SetState(adapter.ConnectionStateConnected)
		first.SetState(adapter.ConnectionStateFailed)
		first.SetState(adapter.ConnectionStateDisconnected)
		requireSelected(t, group, "second")
		second.SetState(adapter.ConnectionStateDisconnected)
		requireSelected(t, group, "first")
		require.Equal(t, []string{
			"outbound first not connected after 10s, falling back to second",
			"no outbound connected, switching to first",
			"outbound second connected, switching from first",
			"outbound first connected, switching back from second",
			"outbound first failed, switching to second",
			"outbound second lost connection, switching to first",
		}, testContext.logger.Messages())
	})
	synctest.Test(t, func(t *testing.T) {
		first := newFallbackTestMember("first", adapter.ConnectionStateFailed)
		second := newFallbackTestMember("second", adapter.ConnectionStateDisconnected)
		testContext := newFallbackTestContext(first, second)
		group := testContext.start(t, "fallback", option.FallbackOutboundOptions{Outbounds: []string{"first", "second"}})
		defer group.Close()
		sleep(C.DefaultFallbackTimeout)
		second.SetState(adapter.ConnectionStateConnected)
		require.Equal(t, []string{
			"outbound first failed, switching to second",
			"no outbound connected, switching to first",
			"outbound second connected, switching from first",
		}, testContext.logger.Messages())
	})
}

func TestFallbackNested(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := newFallbackTestMember("first", adapter.ConnectionStateDisconnected)
		second := newFallbackTestMember("second", adapter.ConnectionStateDisconnected)
		last := newFallbackTestMember("last", adapter.ConnectionStateConnected)
		testContext := newFallbackTestContext(first, second, last)
		inner := testContext.start(t, "inner", option.FallbackOutboundOptions{Outbounds: []string{"first", "second"}})
		defer inner.Close()
		outer := testContext.start(t, "outer", option.FallbackOutboundOptions{Outbounds: []string{"inner", "last"}})
		defer outer.Close()
		requireSelected(t, outer, "inner")
		require.True(t, first.Monitored())
		require.False(t, second.Monitored())
		require.False(t, last.Monitored())
		sleep(C.DefaultFallbackTimeout)
		requireSelected(t, outer, "last")
		require.True(t, second.Monitored())
		second.SetState(adapter.ConnectionStateConnected)
		requireSelected(t, inner, "second")
		requireSelected(t, outer, "inner")
		require.Equal(t, "second", RealTag(outer, N.NetworkTCP))
		require.False(t, last.Monitored())
	})
}

func TestFallbackSharedMember(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := newFallbackTestMember("first", adapter.ConnectionStateConnected)
		shared := newFallbackTestMember("shared", adapter.ConnectionStateDisconnected)
		testContext := newFallbackTestContext(first, shared)
		primary := testContext.start(t, "primary", option.FallbackOutboundOptions{Outbounds: []string{"shared"}})
		defer primary.Close()
		secondary := testContext.start(t, "secondary", option.FallbackOutboundOptions{Outbounds: []string{"first", "shared"}})
		defer secondary.Close()
		first.SetState(adapter.ConnectionStateDisconnected)
		sleep(C.DefaultFallbackTimeout)
		require.Equal(t, []string{"first", "shared"}, secondary.References())
		first.SetState(adapter.ConnectionStateConnected)
		require.Equal(t, []string{"first"}, secondary.References())
		require.True(t, shared.Monitored())
		require.NoError(t, primary.Close())
		require.False(t, shared.Monitored())
	})
}

func TestFallbackClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := newFallbackTestMember("first", adapter.ConnectionStateDisconnected)
		second := newFallbackTestMember("second", adapter.ConnectionStateDisconnected)
		testContext := newFallbackTestContext(first, second)
		group := testContext.start(t, "fallback", option.FallbackOutboundOptions{Outbounds: []string{"first", "second"}})
		sleep(C.DefaultFallbackTimeout)
		require.True(t, first.Monitored())
		require.True(t, second.Monitored())
		require.NoError(t, group.Close())
		require.False(t, first.Monitored())
		require.False(t, second.Monitored())
		first.SetState(adapter.ConnectionStateConnected)
		sleep(time.Hour)
		requireSelected(t, group, "second")
	})
}

func TestFallbackStartRace(t *testing.T) {
	// synctest runs one goroutine at a time, so the race detector needs real time to see the first evaluation race with Start.
	for range 100 {
		first := newFallbackTestMember("first", adapter.ConnectionStateFailed)
		second := newFallbackTestMember("second", adapter.ConnectionStateConnected)
		testContext := newFallbackTestContext(first, second)
		group := testContext.create(t, "fallback", option.FallbackOutboundOptions{Outbounds: []string{"first", "second"}})
		require.Eventually(t, func() bool {
			return group.Selected(N.NetworkTCP).Tag() == "second"
		}, time.Second, time.Millisecond)
		require.NoError(t, group.Close())
	}
}

func TestFallbackInvalidTimeout(t *testing.T) {
	_, err := NewFallback(context.Background(), nil, log.NewNOPFactory().Logger(), "fallback", option.FallbackOutboundOptions{
		Outbounds: []string{"first"},
		Timeout:   badoption.Duration(-time.Second),
	})
	require.Error(t, err)
}

func dialFallback(t *testing.T, group *Fallback, external bool) *fallbackTestConn {
	conn, err := group.DialContext(interrupt.ContextWithIsExternalConnection(context.Background(), external), N.NetworkTCP, M.ParseSocksaddr("1.1.1.1:443"))
	require.NoError(t, err)
	return conn.(*interrupt.Conn).Conn.(*fallbackTestConn)
}
