#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
test_multiav
----------------------------------

Tests for `multiav` module.
"""

import unittest
from multiav.core import AV_SPEED


class TestMultiav(unittest.TestCase):
    def setUp(self):
        pass

    def test_AV_SPEED(self):
        self.output = AV_SPEED.ALL
        pass

    def tearDown(self):
        pass
