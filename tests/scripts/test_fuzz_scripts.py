"""Regression tests for the fuzz matrix planner and the public API coverage check."""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts" / "fuzz"


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PLAN = load("plan")
COVERAGE = load("api_coverage")


class PlanTests(unittest.TestCase):
    def test_glob_double_star_spans_directories_single_star_does_not(self):
        self.assertTrue(PLAN.glob_match("crates/a/src/x/y.rs", "crates/a/src/**"))
        self.assertTrue(PLAN.glob_match("crates/a/src/key_log_file.rs", "crates/a/src/key_log*.rs"))
        self.assertFalse(PLAN.glob_match("crates/a/src/x/y.rs", "crates/a/src/*.rs"))
        self.assertFalse(PLAN.glob_match("crates/ab/src/y.rs", "crates/a/**"))

    def test_repository_target_lists_agree(self):
        self.assertEqual(PLAN.check(), [])

    def test_full_matrix_has_one_entry_per_target(self):
        include = PLAN.matrix("target", None, None)["include"]
        self.assertEqual([e["name"] for e in include], list(PLAN.load_targets()))
        for entry in include:
            self.assertEqual(set(entry), {"name", "targets"})
            self.assertEqual(entry["name"], entry["targets"])

    def test_topic_matrix_groups_targets(self):
        include = PLAN.matrix("topic", None, None)["include"]
        names = [e["name"] for e in include]
        self.assertEqual(len(names), len(set(names)))
        grouped = sorted(t for e in include for t in e["targets"].split())
        self.assertEqual(grouped, sorted(PLAN.load_targets()))

    def test_changed_sources_select_their_targets(self):
        include = PLAN.matrix("target", ["crates/browntls-crypto/src/rsa/mod.rs"], None)["include"]
        self.assertEqual({e["targets"] for e in include}, {"crypto_rsa"})

    def test_changed_harness_selects_its_targets(self):
        include = PLAN.matrix("target", ["fuzz/src/pki.rs"], None)["include"]
        self.assertEqual({e["targets"] for e in include}, {"pki_cert", "pki_pem", "pki_crl"})

    def test_revocation_changes_select_the_revocation_harness(self):
        for path in (
            "crates/browntls/src/revocation/policy/data.rs",
            "crates/browntls/src/quic/connection.rs",
            "crates/browntls-tokio/src/revocation/staple.rs",
            "fuzz/src/pki_revocation/fixtures.rs",
        ):
            include = PLAN.matrix("target", [path], None)["include"]
            self.assertIn("pki_revocation", {e["targets"] for e in include}, path)

    def test_crate_manifest_selects_that_crates_targets(self):
        include = PLAN.matrix("target", ["crates/browntls-pki/Cargo.toml"], None)["include"]
        self.assertEqual(
            {e["targets"] for e in include},
            {"pki_cert", "pki_pem", "pki_crl", "pki_api", "pki_revocation"},
        )

    def test_shared_infrastructure_selects_everything(self):
        for path in ("fuzz/Cargo.lock", "fuzz/src/input.rs", ".github/workflows/fuzz.yml"):
            include = PLAN.matrix("target", [path], None)["include"]
            self.assertEqual(len(include), len(PLAN.load_targets()), path)

    def test_unrelated_change_selects_nothing(self):
        self.assertEqual(PLAN.matrix("target", ["README.md"], None), {"include": []})
        self.assertEqual(json.dumps({"include": []}, separators=(",", ":")), '{"include":[]}')

    def test_target_filter(self):
        include = PLAN.matrix("target", None, {"crypto_hash"})["include"]
        self.assertEqual(include, [{"name": "crypto_hash", "targets": "crypto_hash"}])
        with self.assertRaises(SystemExit):
            PLAN.matrix("target", None, {"no_such_target"})


class ScanTests(unittest.TestCase):
    def scan(self, text):
        with tempfile.TemporaryDirectory(dir=COVERAGE.REPO) as tmp:
            path = Path(tmp) / "lib.rs"
            path.write_text(text)
            return [(f.name, f.line, f.in_macro) for f in COVERAGE.scan_file(path)]

    def test_qualifies_methods_with_their_impl_type(self):
        source = (
            "pub fn free() {}\n"
            "impl<'a, T: Clone> Foo<'a, T> {\n"
            "    pub fn new() -> Self { todo!() }\n"
            "    fn private() {}\n"
            "    pub const fn konst() {}\n"
            "}\n"
            "impl fmt::Display for Bar {\n"
            "    pub fn shown() {}\n"
            "}\n"
            "pub(crate) fn hidden() {}\n"
            "pub unsafe extern \"C\" fn ffi() {}\n"
        )
        self.assertEqual(self.scan(source), [
            ("free", 1, False), ("Foo::new", 3, False), ("Foo::konst", 5, False),
            ("Bar::shown", 8, False), ("ffi", 11, False),
        ])

    def test_skips_test_modules_and_numbers_duplicates(self):
        source = (
            "impl A {\n"
            "    pub fn f() {}\n"
            "}\n"
            "impl A {\n"
            "    pub fn f() {}\n"
            "}\n"
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    pub fn helper() { let s = \"}\"; }\n"
            "}\n"
            "pub fn after() {}\n"
        )
        self.assertEqual(self.scan(source), [("A::f", 2, False), ("A::f#2", 5, False), ("after", 11, False)])

    def test_skips_compound_test_cfgs_but_not_not_test(self):
        source = (
            "#[cfg(all(test, feature = \"std\"))]\n"
            "mod tests {\n"
            "    pub fn helper() {}\n"
            "}\n"
            "#[cfg(not(test))]\n"
            "mod real {\n"
            "    pub fn kept() {}\n"
            "}\n"
        )
        self.assertEqual(self.scan(source), [("kept", 7, False)])

    def test_marks_functions_inside_macros(self):
        source = (
            "macro_rules! make {\n"
            "    ($name:ident) => {\n"
            "        impl $name {\n"
            "            pub fn new() {}\n"
            "        }\n"
            "    };\n"
            "}\n"
            "pub fn outside() {}\n"
        )
        self.assertEqual(self.scan(source), [("$name::new", 4, True), ("outside", 8, False)])


class CheckTests(unittest.TestCase):
    def test_exemption_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "exemptions.txt"
            path.write_text("# comment\n\ncrates/x/src/*.rs Foo::*  # reason here\n")
            (exemption,) = COVERAGE.load_exemptions(path)
            fn = COVERAGE.PublicFn("crates/x/src/a.rs", "Foo::bar", 3, False)
            self.assertTrue(exemption.matches(fn))
            self.assertFalse(exemption.matches(COVERAGE.PublicFn("crates/x/src/a.rs", "Baz::bar", 3, False)))
            path.write_text("crates/x/src/a.rs Foo::bar\n")
            with self.assertRaises(SystemExit):
                COVERAGE.load_exemptions(path)

    def test_counts_generic_any_and_macro_every_instantiation(self):
        root = str(COVERAGE.REPO)
        export = {"data": [{"functions": [
            {"count": 0, "filenames": [f"{root}/crates/x/src/a.rs"], "regions": [[10, 5, 12, 6, 0, 0, 0, 0]]},
            {"count": 4, "filenames": [f"{root}/crates/x/src/a.rs"], "regions": [[10, 5, 12, 6, 4, 0, 0, 0]]},
            {"count": 1, "filenames": ["/elsewhere/b.rs"], "regions": [[1, 1, 1, 2, 1, 0, 0, 0]]},
        ]}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "export.json"
            path.write_text(json.dumps(export))
            most, least = COVERAGE.load_coverage(path)
        self.assertEqual(most, {("crates/x/src/a.rs", 10): 4})
        self.assertEqual(least, {("crates/x/src/a.rs", 10): 0})


if __name__ == "__main__":
    unittest.main()
