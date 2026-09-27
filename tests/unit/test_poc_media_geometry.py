import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("poc_media_geometry", ROOT / "tools/poc_media_geometry.py")
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class GeometryTests(unittest.TestCase):
    def test_exact_three_partition_ranges(self):
        ranges = module.plan(64 * module.GIB)
        self.assertEqual(tuple(x.role for x in ranges), ("esp", "boot_root", "persistence"))
        self.assertEqual(ranges[0].first_lba, 2048)
        self.assertEqual(ranges[0].last_lba + 1, ranges[1].first_lba)
        self.assertEqual(ranges[1].last_lba + 1, ranges[2].first_lba)
        self.assertEqual((ranges[0].last_lba - ranges[0].first_lba + 1) * 512, module.ESP_SIZE)
        self.assertEqual((ranges[1].last_lba - ranges[1].first_lba + 1) * 512, module.ROOT_SIZE)
        self.assertLess(ranges[-1].last_lba, 64 * module.GIB // 512 - 34)

    def test_refuses_small_or_ambiguous_geometry(self):
        for capacity, sector in (
            (31 * module.GIB, 512),
            (64 * module.GIB, 4096),
            (64 * module.GIB + 1, 512),
            (True, 512),
        ):
            with self.subTest(capacity=capacity, sector=sector), self.assertRaises(ValueError):
                module.plan(capacity, sector)


if __name__ == "__main__":
    unittest.main()
