# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import unittest

from cylance_validation import normalize_uuid


class NormalizeUuidTests(unittest.TestCase):
    def test_normalizes_valid_uuid(self):
        self.assertEqual(
            normalize_uuid("550E8400-E29B-41D4-A716-446655440000"),
            "550e8400-e29b-41d4-a716-446655440000",
        )

    def test_rejects_path_and_dot_segments(self):
        invalid_values = (".", "..", "../../users/v2", "../../users/v2?", "device/id")

        for value in invalid_values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_uuid(value)


if __name__ == "__main__":
    unittest.main()
