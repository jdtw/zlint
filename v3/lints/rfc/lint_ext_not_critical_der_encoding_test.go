package rfc

/*
 * ZLint Copyright 2023 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func TestIncorrectCriticalDEREncoding(t *testing.T) {
	data := []struct {
		file string
		want lint.LintStatus
	}{{
		"incorrectCriticalDEREncoding.pem", lint.Error,
	}, {
		"facebookOnionV3Address.pem", lint.Pass,
	}}
	for _, testData := range data {
		data := testData
		t.Run(data.file, func(t *testing.T) {
			out := test.TestLint("e_ext_not_critical_omits_default", data.file)
			if out.Status != data.want {
				t.Errorf("%s: got %v, want %v", data.file, out, data.want)
			}
		})
	}
}
