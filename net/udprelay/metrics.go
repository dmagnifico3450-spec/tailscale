// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package udprelay

import (
	"expvar"

	"tailscale.com/util/usermetric"
)

type network string

const (
	networkIPv4 network = "ipv4"
	networkIPv6 network = "ipv6"
)

type proto string

const (
	protoUnknown   = "unknown"
	protoGeneveUDP = "geneve_udp"
	protoSTUN      = "stun"
	protoDisco     = "disco"
)

type discard string

const (
	discardMalformed      = "malformed"
	discardUnknownControl = "unknown_control"
	discardUnknownVNI     = "unknown_vni"
	discardUnknownPeer    = "unknown_peer"
)

type metricLabel struct {
	network network
	proto   proto
	discard discard
}

type metrics struct {
	stun4Packets               expvar.Int
	stun6Packets               expvar.Int
	unknown4DiscardPackets     expvar.Int
	unknown6DiscardPackets     expvar.Int
	disco4Packets              expvar.Int
	disco6Packets              expvar.Int
	disco4MalformedPackets     expvar.Int
	disco6MalformedPackets     expvar.Int
	data4Packets               expvar.Int
	data6Packets               expvar.Int
	data4UnknownVNIPackets     expvar.Int
	data6UnknownVNIPackets     expvar.Int
	data4UnknownControlPackets expvar.Int
	data6UnknownControlPackets expvar.Int
	data4UnknownPeerPackets    expvar.Int
	data6UnknownPeerPackets    expvar.Int

	stun4Bytes               expvar.Int
	stun6Bytes               expvar.Int
	unknown4DiscardBytes     expvar.Int
	unknown6DiscardBytes     expvar.Int
	disco4Bytes              expvar.Int
	disco6Bytes              expvar.Int
	disco4MalformedBytes     expvar.Int
	disco6MalformedBytes     expvar.Int
	data4Bytes               expvar.Int
	data6Bytes               expvar.Int
	data4UnknownVNIBytes     expvar.Int
	data6UnknownVNIBytes     expvar.Int
	data4UnknownControlBytes expvar.Int
	data6UnknownControlBytes expvar.Int
	data4UnknownPeerBytes    expvar.Int
	data6UnknownPeerBytes    expvar.Int
}

// registerMetrics publishes user metric counters for peer relay server.
func registerMetrics(reg *usermetric.Registry) *metrics {
	receivedPackets := usermetric.NewMultiLabelMapWithRegistry[metricLabel](
		reg,
		"tailscaled_relay_received_packets_total",
		"counter",
		"Counts the number of packets received from other peers",
	)
	receivedBytes := usermetric.NewMultiLabelMapWithRegistry[metricLabel](
		reg,
		"tailscaled_relay_received_bytes_total",
		"counter",
		"Counts the number of bytes received from other peers",
	)
	var (
		stun4               = metricLabel{network: networkIPv4, proto: protoSTUN}
		stun6               = metricLabel{network: networkIPv6, proto: protoSTUN}
		unknown4Discard     = metricLabel{network: networkIPv4, proto: protoUnknown, discard: discardMalformed}
		unknown6Discard     = metricLabel{network: networkIPv6, proto: protoUnknown, discard: discardMalformed}
		disco4              = metricLabel{network: networkIPv4, proto: protoDisco}
		disco6              = metricLabel{network: networkIPv6, proto: protoDisco}
		disco4Malformed     = metricLabel{network: networkIPv4, proto: protoDisco, discard: discardMalformed}
		disco6Malformed     = metricLabel{network: networkIPv6, proto: protoDisco, discard: discardMalformed}
		data4               = metricLabel{network: networkIPv4, proto: protoGeneveUDP}
		data6               = metricLabel{network: networkIPv6, proto: protoGeneveUDP}
		data4UnknownControl = metricLabel{network: networkIPv4, proto: protoGeneveUDP, discard: discardUnknownControl}
		data6UnknownControl = metricLabel{network: networkIPv6, proto: protoGeneveUDP, discard: discardUnknownControl}
		data4UnknownVNI     = metricLabel{network: networkIPv4, proto: protoGeneveUDP, discard: discardUnknownVNI}
		data6UnknownVNI     = metricLabel{network: networkIPv6, proto: protoGeneveUDP, discard: discardUnknownVNI}
		data4UnknownPeer    = metricLabel{network: networkIPv4, proto: protoGeneveUDP, discard: discardUnknownPeer}
		data6UnknownPeer    = metricLabel{network: networkIPv6, proto: protoGeneveUDP, discard: discardUnknownPeer}
		m                   = new(metrics)
	)

	receivedPackets.Set(stun4, &m.stun4Packets)
	receivedPackets.Set(stun6, &m.stun6Packets)
	receivedBytes.Set(stun4, &m.stun4Bytes)
	receivedBytes.Set(stun6, &m.stun6Bytes)

	receivedPackets.Set(unknown4Discard, &m.unknown4DiscardPackets)
	receivedPackets.Set(unknown6Discard, &m.unknown6DiscardPackets)
	receivedBytes.Set(unknown4Discard, &m.unknown4DiscardBytes)
	receivedBytes.Set(unknown6Discard, &m.unknown6DiscardBytes)

	receivedPackets.Set(disco4, &m.disco4Packets)
	receivedPackets.Set(disco6, &m.disco6Packets)
	receivedBytes.Set(disco4, &m.disco4Bytes)
	receivedBytes.Set(disco6, &m.disco6Bytes)

	receivedPackets.Set(disco4Malformed, &m.disco4MalformedPackets)
	receivedPackets.Set(disco6Malformed, &m.disco6MalformedPackets)
	receivedBytes.Set(disco4Malformed, &m.disco4MalformedBytes)
	receivedBytes.Set(disco6Malformed, &m.disco6MalformedBytes)

	receivedPackets.Set(data4, &m.data4Packets)
	receivedPackets.Set(data6, &m.data6Packets)
	receivedBytes.Set(data4, &m.data4Bytes)
	receivedBytes.Set(data6, &m.data6Bytes)

	receivedPackets.Set(data4UnknownVNI, &m.data4UnknownVNIPackets)
	receivedPackets.Set(data6UnknownVNI, &m.data6UnknownVNIPackets)
	receivedBytes.Set(data4UnknownVNI, &m.data4UnknownVNIBytes)
	receivedBytes.Set(data6UnknownVNI, &m.data6UnknownVNIBytes)

	receivedPackets.Set(data4UnknownControl, &m.data4UnknownControlPackets)
	receivedPackets.Set(data6UnknownControl, &m.data6UnknownControlPackets)
	receivedBytes.Set(data4UnknownControl, &m.data4UnknownControlBytes)
	receivedBytes.Set(data6UnknownControl, &m.data6UnknownControlBytes)

	receivedPackets.Set(data4UnknownPeer, &m.data4UnknownPeerPackets)
	receivedPackets.Set(data6UnknownPeer, &m.data6UnknownPeerPackets)
	receivedBytes.Set(data4UnknownPeer, &m.data4UnknownPeerBytes)
	receivedBytes.Set(data6UnknownPeer, &m.data6UnknownPeerBytes)

	return m
}

func (m *metrics) countSTUN(is4 bool, bytes int64) {
	if is4 {
		m.stun4Bytes.Add(bytes)
		m.stun4Packets.Add(1)
		return
	}
	m.stun6Bytes.Add(bytes)
	m.stun6Packets.Add(1)
}

func (m *metrics) countNonGeneve(is4 bool, bytes int64) {
	if is4 {
		m.unknown4DiscardBytes.Add(bytes)
		m.unknown4DiscardPackets.Add(1)
		return
	}
	m.unknown6DiscardBytes.Add(bytes)
	m.unknown6DiscardPackets.Add(1)
}

func (m *metrics) countUnknownVNI(is4 bool, bytes int64) {
	if is4 {
		m.data4UnknownVNIBytes.Add(bytes)
		m.data4UnknownVNIPackets.Add(1)
		return
	}
	m.data6UnknownVNIBytes.Add(bytes)
	m.data6UnknownVNIPackets.Add(1)
}

func (m *metrics) countUnknownControl(is4 bool, bytes int64) {
	if is4 {
		m.data4UnknownControlBytes.Add(bytes)
		m.data4UnknownControlPackets.Add(1)
		return
	}
	m.data6UnknownControlBytes.Add(bytes)
	m.data6UnknownControlPackets.Add(1)
}

func (m *metrics) countDiscoMalformed(is4 bool, bytes int64) {
	if is4 {
		m.disco4MalformedBytes.Add(bytes)
		m.disco4MalformedPackets.Add(1)
		return
	}
	m.disco6MalformedBytes.Add(bytes)
	m.disco6MalformedPackets.Add(1)
}

func (m *metrics) countDiscoRx(is4 bool, bytes int64) {
	if is4 {
		m.disco4Bytes.Add(bytes)
		m.disco4Packets.Add(1)
		return
	}
	m.disco6Bytes.Add(bytes)
	m.disco6Packets.Add(1)
}

func (m *metrics) countDataMalformed(is4 bool, bytes int64) {
	if is4 {
		m.data4UnknownPeerBytes.Add(bytes)
		m.data4UnknownPeerPackets.Add(1)
		return
	}
	m.data6UnknownPeerBytes.Add(bytes)
	m.data6UnknownPeerPackets.Add(1)
}

func (m *metrics) countDataRelayed(is4 bool, bytes int64) {
	if is4 {
		m.data4Bytes.Add(bytes)
		m.data4Packets.Add(1)
		return
	}
	m.data6Bytes.Add(bytes)
	m.data6Packets.Add(1)
}
