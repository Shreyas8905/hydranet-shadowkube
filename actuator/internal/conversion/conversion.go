// Package conversion: conversion.go orchestrates the three phases of an
// in-situ honeypot conversion. Returns the populated state.Record.
package conversion

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/shadowkube-repro/actuator/internal/state"
)

// Alarm is the subset of the detector's webhook payload the actuator needs.
type Alarm struct {
	Group    string // e.g. "labels:group=weather-app"
	Node     string // node the compromised pod runs on
	Pod      string // pod UID
	PodIP    string // pod IP (for iptables)
	SourceIP string // external attacker IP if extractable (for proxy blacklist)
}

// Run executes the three phases sequentially and records per-phase
// timings. Returns the final state.Record.
//
// phase1Params describes the redirection; phase1Params is required even
// in dry-run mode (we log what we would have done).
func Run(ctx context.Context, k *Kube, alarm Alarm, p RedirectParams, actOnAlarm bool, nodeCount int) (*state.Record, error) {
	rec := &state.Record{
		Alarm:     time.Now(),
		StartedAt: time.Now(),
		Group:     alarm.Group,
		Node:      alarm.Node,
		Pod:       alarm.Pod,
		PodIP:     alarm.PodIP,
		Decision:  state.DecisionConvertInSitu,
	}

	if err := Phase1(ctx, k, rec, p, actOnAlarm); err != nil {
		return rec, fmt.Errorf("phase1: %w", err)
	}
	deleted, err := Phase2(ctx, k, rec, alarm.Pod, alarm.Node, actOnAlarm)
	if err != nil {
		return rec, fmt.Errorf("phase2: %w", err)
	}
	log.Printf("conversion: phase2 deleted %d sibling pods on node %s", deleted, alarm.Node)

	if err := Phase3(ctx, rec, alarm.Pod, alarm.Node, actOnAlarm); err != nil {
		return rec, fmt.Errorf("phase3: %w", err)
	}

	rec.Timings.Total = time.Since(rec.StartedAt)
	return rec, nil
}