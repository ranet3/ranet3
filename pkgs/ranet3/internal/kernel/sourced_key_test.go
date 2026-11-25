// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/schema"
)

func TestSourcedTableID(t *testing.T) {
	to := []schema.Prefix{schema.MustPrefix("2001:db8:ffff::/48")}
	for _, tc := range []struct {
		mesh, sourced schema.TableID
		want          schema.TableID
		err           string
	}{
		{mesh: 0, sourced: 0, want: 201},
		{mesh: 200, sourced: 0, want: 201},
		{mesh: 300, sourced: 0, want: 301},
		{mesh: 300, sourced: 302, want: 302},
		{mesh: 252, sourced: 0, err: "cannot be derived from cap.table.id 252, write id"},
		{mesh: 4294967295, sourced: 0, err: "cannot be derived from cap.table.id 4294967295, write id"},
		{mesh: 252, sourced: 300, want: 300},
		{mesh: 200, sourced: 200, err: "id 200 is reserved or equals cap.table.id"},
		{mesh: 300, sourced: 300, err: "id 300 is reserved or equals cap.table.id"},
		{mesh: 200, sourced: 253, err: "id 253 is reserved or equals cap.table.id"},
		{mesh: 200, sourced: 254, err: "id 254 is reserved or equals cap.table.id"},
		{mesh: 200, sourced: 255, err: "id 255 is reserved or equals cap.table.id"},
	} {
		table := Table{ID: tc.mesh, Sourced: &Sourced{To: to, ID: tc.sourced}}
		if err := table.Validate(); tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%d/%d: %v, want %s", tc.mesh, tc.sourced, err, tc.err)
			}
		} else if err != nil {
			t.Errorf("%d/%d: %v", tc.mesh, tc.sourced, err)
		} else if got := table.Normalized().Sourced.ID; got != tc.want {
			t.Errorf("%d/%d: normalized %d, want %d", tc.mesh, tc.sourced, got, tc.want)
		}
	}
}
