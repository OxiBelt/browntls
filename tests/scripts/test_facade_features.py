"""Regression coverage for the facade feature check."""

import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "check_facade_features", Path(__file__).with_name("check_facade_features.py")
)
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)

WORKSPACE = """\
[workspace.dependencies]
browntls-core = { path = "crates/browntls-core", default-features = false }
browntls-tokio = { path = "crates/browntls-tokio", default-features = false }
"""
CORE = """\
[features]
default = ["std", "tls12"]
std = []
tls12 = []
fuzzing = ["std"]
"""
TOKIO = """\
[features]
default = ["tls12", "coop"]
coop = []
tls12 = ["browntls-core/tls12"]
"""
FACADE = """\
[features]
default = ["std", "tls12", "coop"]
tokio = ["std", "dep:browntls-tokio"]
coop = ["browntls-tokio?/coop"]
std = ["browntls-core/std"]
tls12 = ["browntls-core/tls12", "browntls-tokio?/tls12"]

[dependencies]
browntls-core = { workspace = true }
browntls-tokio = { workspace = true, optional = true }
"""


class FacadeFeatureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.write("Cargo.toml", WORKSPACE)
        self.write("crates/browntls-core/Cargo.toml", CORE)
        self.write("crates/browntls-tokio/Cargo.toml", TOKIO)
        self.write("crates/browntls/Cargo.toml", FACADE)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def replace(self, name, old, new):
        path = self.root / name
        text = path.read_text()
        self.assertIn(old, text)
        path.write_text(text.replace(old, new))

    def messages(self):
        return [item.render() for item in CHECKER.check(self.root)]

    def facade(self, message):
        return f"crates/browntls/Cargo.toml: {message}"

    def test_tables_in_step_pass(self):
        self.assertEqual([], self.messages())

    def test_the_repository_itself_passes(self):
        self.assertEqual([], CHECKER.check(Path(__file__).resolve().parents[2]))

    def test_new_core_feature_must_be_offered(self):
        self.replace("crates/browntls-core/Cargo.toml", "tls12 = []", "tls12 = []\nzlib = []")
        self.assertEqual(
            [self.facade("feature `zlib` of `browntls-core` is missing")], self.messages()
        )

    def test_feature_must_enable_the_core_feature(self):
        self.replace("crates/browntls/Cargo.toml", '"browntls-core/tls12", ', "")
        self.assertEqual(
            [self.facade("feature `tls12` does not enable `browntls-core/tls12`")],
            self.messages(),
        )

    def test_feature_must_reach_the_optional_crate(self):
        self.replace("crates/browntls/Cargo.toml", ', "browntls-tokio?/tls12"', "")
        self.assertEqual(
            [self.facade("feature `tls12` does not enable `browntls-tokio?/tls12`")],
            self.messages(),
        )

    def test_new_optional_crate_feature_must_be_offered(self):
        self.replace("crates/browntls-tokio/Cargo.toml", "coop = []", "coop = []\nocsp = []")
        self.assertEqual(
            [self.facade("feature `ocsp` of `browntls-tokio` is missing")], self.messages()
        )

    def test_a_strong_reference_to_the_optional_crate_counts(self):
        self.replace("crates/browntls-tokio/Cargo.toml", "coop = []", "coop = []\nocsp = []")
        self.replace(
            "crates/browntls/Cargo.toml",
            'coop = ["browntls-tokio?/coop"]',
            'coop = ["browntls-tokio?/coop"]\nocsp = ["tokio", "browntls-tokio/ocsp"]',
        )
        self.assertEqual([], self.messages())

    def test_a_strong_reference_must_not_pull_the_optional_crate_in(self):
        self.replace("crates/browntls/Cargo.toml", '"browntls-tokio?/tls12"', '"browntls-tokio/tls12"')
        self.assertEqual(
            [
                self.facade(
                    "feature `tls12` enables `browntls-tokio/tls12`, which pulls in the "
                    "optional `browntls-tokio`: use `browntls-tokio?/tls12`"
                )
            ],
            self.messages(),
        )

    def test_a_weak_reference_does_not_excuse_a_strong_one(self):
        self.replace(
            "crates/browntls/Cargo.toml",
            '"browntls-tokio?/tls12"',
            '"browntls-tokio?/tls12", "browntls-tokio/tls12"',
        )
        self.assertEqual(
            [
                self.facade(
                    "feature `tls12` enables `browntls-tokio/tls12`, which pulls in the "
                    "optional `browntls-tokio`: use `browntls-tokio?/tls12`"
                )
            ],
            self.messages(),
        )

    def test_a_default_feature_must_not_enable_an_optional_crate(self):
        self.replace(
            "crates/browntls/Cargo.toml",
            'tls12 = ["browntls-core/tls12", ',
            'tls12 = ["tokio", "browntls-core/tls12", ',
        )
        self.assertEqual(
            [
                self.facade(
                    "default feature `tls12` enables the optional dependency `browntls-tokio`"
                )
            ],
            self.messages(),
        )
        self.replace(
            "crates/browntls/Cargo.toml",
            'tls12 = ["tokio", "browntls-core/tls12", ',
            'tls12 = ["browntls-core/tls12", ',
        )
        self.replace(
            "crates/browntls/Cargo.toml",
            'default = ["std", "tls12", "coop"]',
            'default = ["std", "tls12", "coop", "dep:browntls-tokio"]',
        )
        self.assertIn(
            self.facade(
                "default feature `dep:browntls-tokio` enables the optional dependency "
                "`browntls-tokio`"
            ),
            self.messages(),
        )

    def test_a_feature_of_another_name_is_reported(self):
        self.replace(
            "crates/browntls/Cargo.toml",
            'std = ["browntls-core/std"]',
            'std = ["browntls-core/std", "browntls-core/tls12", "browntls-tokio?/coop"]',
        )
        self.assertEqual(
            [
                self.facade("feature `std` enables `browntls-core/tls12`, a feature of another name"),
                self.facade("feature `std` enables `browntls-tokio?/coop`, a feature of another name"),
            ],
            self.messages(),
        )

    def test_not_offered_features_cannot_hide_in_another_feature(self):
        self.replace(
            "crates/browntls/Cargo.toml",
            'std = ["browntls-core/std"]',
            'std = ["browntls-core/std", "browntls-core/fuzzing"]',
        )
        self.assertEqual(
            [self.facade("feature `std` enables `browntls-core/fuzzing`, which `NOT_OFFERED` names")],
            self.messages(),
        )

    def test_target_specific_dependencies_are_checked(self):
        self.replace(
            "crates/browntls/Cargo.toml",
            "browntls-tokio = { workspace = true, optional = true }\n",
            "\n[target.'cfg(unix)'.dependencies]\n"
            "browntls-tokio = { workspace = true, optional = true }\n",
        )
        self.assertEqual([], self.messages())
        self.replace("crates/browntls/Cargo.toml", ', "browntls-tokio?/tls12"', "")
        self.assertEqual(
            [self.facade("feature `tls12` does not enable `browntls-tokio?/tls12`")],
            self.messages(),
        )

    def test_a_direct_default_features_setting_counts(self):
        self.replace(
            "crates/browntls/Cargo.toml",
            "browntls-core = { workspace = true }",
            'browntls-core = { path = "../browntls-core", default-features = false }',
        )
        self.assertEqual([], self.messages())

    def test_not_offered_features_stay_out(self):
        self.replace(
            "crates/browntls/Cargo.toml",
            'std = ["browntls-core/std"]',
            'std = ["browntls-core/std"]\nfuzzing = ["browntls-core/fuzzing"]',
        )
        self.assertEqual(
            [
                self.facade(
                    "feature `fuzzing` enables `browntls-core/fuzzing`, which `NOT_OFFERED` names"
                ),
                self.facade("feature `fuzzing` is offered although `NOT_OFFERED` names it"),
            ],
            self.messages(),
        )

    def test_stale_not_offered_entry_is_reported(self):
        self.replace("crates/browntls-core/Cargo.toml", 'fuzzing = ["std"]\n', "")
        self.assertEqual(
            [self.facade("`NOT_OFFERED` names `fuzzing`, which `browntls-core` does not have")],
            self.messages(),
        )

    def test_defaults_of_the_crates_behind_are_defaults(self):
        self.replace(
            "crates/browntls/Cargo.toml",
            'default = ["std", "tls12", "coop"]',
            'default = ["std", "tls12"]',
        )
        self.assertEqual(
            [self.facade("default feature `coop` of `browntls-tokio` is not a default feature")],
            self.messages(),
        )

    def test_defaults_come_from_a_crate_behind(self):
        self.replace(
            "crates/browntls/Cargo.toml",
            'default = ["std", "tls12", "coop"]',
            'default = ["std", "tls12", "coop", "extra"]',
        )
        self.assertEqual(
            [
                self.facade(
                    "default feature `extra` is not a default feature of a crate behind the facade"
                )
            ],
            self.messages(),
        )

    def test_optional_crate_needs_a_feature_that_enables_it(self):
        self.replace("crates/browntls/Cargo.toml", ', "dep:browntls-tokio"', "")
        self.assertEqual(
            [
                self.facade(
                    "no feature enables the optional dependency `browntls-tokio` "
                    "(`dep:browntls-tokio`)"
                )
            ],
            self.messages(),
        )

    def test_dependencies_must_leave_defaults_off(self):
        self.replace(
            "Cargo.toml",
            'browntls-core = { path = "crates/browntls-core", default-features = false }',
            'browntls-core = { path = "crates/browntls-core" }',
        )
        self.replace(
            "crates/browntls/Cargo.toml",
            "browntls-tokio = { workspace = true, optional = true }",
            'browntls-tokio = { path = "../browntls-tokio", optional = true }',
        )
        self.assertEqual(
            [
                self.facade("dependency `browntls-core` must set `default-features = false`"),
                self.facade("dependency `browntls-tokio` must set `default-features = false`"),
            ],
            self.messages(),
        )

    def test_missing_core_dependency_is_reported(self):
        self.replace("crates/browntls/Cargo.toml", "browntls-core = { workspace = true }\n", "")
        self.assertEqual([self.facade("`browntls-core` is not a dependency")], self.messages())

    def test_main_reports_the_result(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(0, CHECKER.main(["--repo-root", str(self.root)]))
        self.assertIn("validated the features of `browntls`", stdout.getvalue())

        self.replace("crates/browntls/Cargo.toml", ', "browntls-tokio?/tls12"', "")
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(1, CHECKER.main(["--repo-root", str(self.root)]))
        self.assertIn("failed with 1 error(s)", stderr.getvalue())

    def test_main_reports_a_malformed_manifest(self):
        for text in ("[features\n", "[features]\nstd = 1\n", "features = 1\n"):
            self.write("crates/browntls-core/Cargo.toml", text)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(2, CHECKER.main(["--repo-root", str(self.root)]))
            self.assertIn("could not start", stderr.getvalue())

    def test_main_reports_a_malformed_dependency_table(self):
        for name, text in (
            ("crates/browntls/Cargo.toml", "dependencies = 1\n"),
            ("crates/browntls/Cargo.toml", "target = 1\n"),
            ("Cargo.toml", "workspace = 1\n"),
            ("Cargo.toml", "[workspace]\ndependencies = 1\n"),
        ):
            self.write("Cargo.toml", WORKSPACE)
            self.write("crates/browntls/Cargo.toml", FACADE)
            self.write(name, text)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(2, CHECKER.main(["--repo-root", str(self.root)]))
            self.assertIn("is not a table", stderr.getvalue())

    def test_main_reports_an_unreadable_manifest(self):
        (self.root / "crates/browntls/Cargo.toml").unlink()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(2, CHECKER.main(["--repo-root", str(self.root)]))
        self.assertIn("could not start", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
