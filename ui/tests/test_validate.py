"""Schema validation rules with the human messages from the brief."""
import shutil
import unittest

from helpers import make_config_tree

import config_schema as schema
import render


class ValidationTest(unittest.TestCase):

    def test_gateway_outside_subnet_rejected(self):
        cfg = dict(schema.defaults())
        cfg["gateway_ip"] = "10.13.0.1"      # outside 10.12.194.0/24
        cfg["subnet"] = "10.12.194.0/24"
        errors = schema.validate(cfg)
        self.assertIn("gateway_ip", [e["key"] for e in errors],
                      f"expected gateway_ip error, got {errors}")
        msg = " ".join(e["message"] for e in errors if e["key"] == "gateway_ip")
        self.assertIn("must lie inside subnet", msg)

        # the real defect: a subnet change with the stale default gateway
        cfg["subnet"] = "10.44.0.0/24"
        errors = schema.validate(cfg)
        self.assertIn("gateway_ip", [e["key"] for e in errors])

    def test_duplicate_ports_rejected(self):
        cfg = dict(schema.defaults())
        cfg["dns_port"] = cfg["trans_port"]  # both 9040
        errors = schema.validate(cfg)
        keys = [e["key"] for e in errors]
        self.assertIn("dns_port", keys, f"expected port error, got {errors}")
        self.assertTrue(
            any("distinct" in e["message"] for e in errors),
            f"expected a 'must be distinct' message, got {errors}")
        # ui_port must not collide with tor ports or 80
        cfg2 = dict(schema.defaults())
        cfg2["ui_port"] = "9050"
        errors = [e for e in schema.validate(cfg2) if e["key"] == "ui_port"]
        self.assertTrue(errors and "collide" in errors[0]["message"])
        cfg2["ui_port"] = "80"
        errors = [e for e in schema.validate(cfg2) if e["key"] == "ui_port"]
        self.assertTrue(errors and "port 80" in errors[0]["message"])

    def test_invalid_cidr_rejected(self):
        for bad in ("10.0.0.0/33", "not-a-cidr", "10.0.0.0"):
            cfg = dict(schema.defaults())
            cfg["subnet"] = bad
            errors = schema.validate(cfg)
            self.assertIn("subnet", [e["key"] for e in errors],
                          f"{bad!r} must be rejected, got {errors}")
        cfg = dict(schema.defaults())
        cfg["virtual_addr_network"] = "10.192.0.0/4"  # prefix < 8
        errors = schema.validate(cfg)
        self.assertIn("virtual_addr_network", [e["key"] for e in errors])

    def test_current_files_parse_clean(self):
        """A populated config tree must parse cleanly and validate."""
        tree = make_config_tree()
        try:
            parsed = render.read_current(tree)
            self.assertEqual(parsed["warnings"], [])
            self.assertEqual(schema.validate(parsed["values"]), [])
        finally:
            shutil.rmtree(tree, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
