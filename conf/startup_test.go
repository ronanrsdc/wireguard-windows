/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/windows/driver"
)

func TestStartWithWindows(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix string
		want   bool
	}{
		{"default", "", false},
		{"enabled", "# WireGuard: StartWithWindows = true\n", true},
		{"disabled", "# WireGuard: StartWithWindows = false\n", false},
		{"whitespace", "  # wireguard: startwithwindows = true \r\n", true},
		{"ordinary comment", "# StartWithWindows = true\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := FromWgQuick(tc.prefix+testInput, "test")
			if !noError(t, err) {
				return
			}
			equal(t, tc.want, c.StartWithWindows)
			reparsed, err := FromWgQuick(c.ToWgQuick(), "renamed")
			if noError(t, err) {
				equal(t, tc.want, reparsed.StartWithWindows)
				equal(t, c.Interface, reparsed.Interface)
				equal(t, c.Peers, reparsed.Peers)
			}
		})
	}
}

func TestStartWithWindowsRoundTrip(t *testing.T) {
	c, err := FromWgQuick("# user comment\n"+testInput, "test")
	if !noError(t, err) {
		return
	}
	c.StartWithWindows = true
	exported := c.ToWgQuick()
	reparsed, err := FromWgQuick(exported, "test")
	if !noError(t, err) {
		return
	}
	equal(t, c, reparsed)
	equal(t, exported, reparsed.ToWgQuick())
	if strings.Count(exported, "# WireGuard: StartWithWindows = true\n") != 1 {
		t.Fatal("expected exactly one startup preference comment")
	}

	// Clearing the checkbox must remove the preference instead of retaining
	// a stale comment that re-enables automatic startup on the next load.
	reparsed.StartWithWindows = false
	manual := reparsed.ToWgQuick()
	if strings.Contains(manual, startWithWindowsKey) {
		t.Fatal("disabled startup preference remained in the exported config")
	}
	c.StartWithWindows = false
	reparsed, err = FromWgQuick(manual, "test")
	if noError(t, err) {
		equal(t, c, reparsed)
	}
}

func TestStartWithWindowsComments(t *testing.T) {
	if _, err := FromWgQuick("# WireGuard: StartWithWindows = invalid\n"+testInput, "test"); err == nil {
		t.Error("accepted an invalid startup preference")
	}

	// Only standalone metadata before the interface section is interpreted.
	c, err := FromWgQuick(testInput+"\n# WireGuard: StartWithWindows = true\n", "test")
	if noError(t, err) {
		equal(t, false, c.StartWithWindows)
		equal(t, []string{"# WireGuard: StartWithWindows = true"}, c.TrailingComments)
	}
}

func TestRuntimeConfigStartWithWindows(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		stored := &Config{Name: "test", StartWithWindows: enabled}
		runtime := FromDriverConfiguration(&driver.Interface{}, stored)
		equal(t, enabled, runtime.StartWithWindows)
	}
}
