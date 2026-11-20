#!/usr/bin/env python3
"""Keep the feature table of the `browntls` facade crate in step.

`crates/browntls` holds no code: it re-exports `browntls-core` and, behind
optional dependencies, `browntls-tokio` and `browntls-ktls`. Its features must
therefore mirror theirs, and a feature added to one of those crates is easy
to forget here. This check reads the manifests and fails unless:

- every feature of the core crate, except the ones in `NOT_OFFERED`, exists
  in the facade under the same name and turns the core feature on;
- every feature of an optional crate exists in the facade under the same
  name, and the facade feature turns it on: weakly (`crate?/feature`), so
  that the feature does not pull the crate in, or strongly
  (`crate/feature`) where the facade feature enables the crate (`dep:crate`,
  directly or through another facade feature);
- a strong reference to an optional crate stands only in a facade feature
  that enables the crate, also where a weak reference stands next to it;
- a facade feature turns on no feature of another name in the crates behind
  it, and none that `NOT_OFFERED` names;
- the facade's default set holds the core crate's and every optional crate's
  default set, and nothing that is not a default of one of them;
- no default feature enables an optional crate, directly or through another
  facade feature;
- every optional crate is turned on by a facade feature (`dep:crate`);
- the facade takes the crates behind it without their default features, so
  that the facade's own feature set decides what is built.

Dependencies are read from `[dependencies]` and from every
`[target.*.dependencies]` table. The crates behind the facade are expected
in `crates/<name>`.

It checks the manifests only. It does not check that the crates build with
every combination of features (the Rust workflow builds a set of
combinations), nor that `tokio` and `ktls` keep `std` in their lists.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path


FACADE = "browntls"
CORE = "browntls-core"
# Core features the facade deliberately does not offer, with the reason.
NOT_OFFERED = {
    "fuzzing": "unstable entry points for the fuzz targets, not a supported API",
}


@dataclass(frozen=True, order=True)
class Diagnostic:
    path: str
    message: str

    def render(self) -> str:
        return f"{self.path}: {self.message}"


def _load(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _table(parent: dict, key: str, path: str) -> dict:
    table = parent.get(key, {})
    if not isinstance(table, dict):
        raise ValueError(f"{path}: `{key}` is not a table")
    return table


def _features(manifest: dict, path: str) -> dict[str, list[str]]:
    table = _table(manifest, "features", path)
    for name, items in table.items():
        if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
            raise ValueError(f"{path}: feature `{name}` is not a list of strings")
    return {name: list(items) for name, items in table.items()}


def _dependencies(manifest: dict, path: str) -> dict[str, object]:
    """`[dependencies]` and every `[target.*.dependencies]`, by name."""
    found: dict[str, object] = dict(_table(manifest, "dependencies", path))
    for table in _table(manifest, "target", path).values():
        if isinstance(table, dict):
            found.update(_table(table, "dependencies", path))
    return found


def _without_defaults(entry: object, workspace_entry: object) -> bool:
    """Whether a dependency entry leaves the dependency's defaults off."""
    if not isinstance(entry, dict):
        return False
    if "default-features" in entry:
        return entry["default-features"] is False
    if entry.get("workspace") is True and isinstance(workspace_entry, dict):
        return workspace_entry.get("default-features") is False
    return False


def _reachable(features: dict[str, list[str]], start: str) -> set[str]:
    """Every entry `start` lists, following the facade's own feature names."""
    seen: set[str] = set()
    pending = [start]
    while pending:
        for item in features.get(pending.pop(), []):
            if item not in seen:
                seen.add(item)
                pending.append(item)
    return seen


def check(repo_root: Path) -> list[Diagnostic]:
    """Returns what is out of step between the facade and the crates behind it."""
    crates = repo_root / "crates"
    facade_path = f"crates/{FACADE}/Cargo.toml"
    facade = _load(crates / FACADE / "Cargo.toml")
    workspace = _table(_load(repo_root / "Cargo.toml"), "workspace", "Cargo.toml")
    workspace_deps = _table(workspace, "dependencies", "Cargo.toml")
    features = _features(facade, facade_path)
    dependencies = _dependencies(facade, facade_path)
    diagnostics: list[Diagnostic] = []

    def report(message: str) -> None:
        diagnostics.append(Diagnostic(facade_path, message))

    if CORE not in dependencies:
        report(f"`{CORE}` is not a dependency")
        return diagnostics
    optional = sorted(
        name
        for name, entry in dependencies.items()
        if isinstance(entry, dict) and entry.get("optional") is True
    )
    behind = {
        name: _features(_load(crates / name / "Cargo.toml"), f"crates/{name}/Cargo.toml")
        for name in [CORE, *optional]
    }

    for name in behind:
        if not _without_defaults(dependencies[name], workspace_deps.get(name)):
            report(f"dependency `{name}` must set `default-features = false`")

    for feature in sorted(behind[CORE]):
        if feature == "default" or feature in NOT_OFFERED:
            continue
        if feature not in features:
            report(f"feature `{feature}` of `{CORE}` is missing")
        elif f"{CORE}/{feature}" not in features[feature]:
            report(f"feature `{feature}` does not enable `{CORE}/{feature}`")
    for feature in sorted(NOT_OFFERED):
        if feature not in behind[CORE]:
            report(f"`NOT_OFFERED` names `{feature}`, which `{CORE}` does not have")
        elif feature in features:
            report(f"feature `{feature}` is offered although `NOT_OFFERED` names it")

    for crate in optional:
        if not any(f"dep:{crate}" in items for items in features.values()):
            report(f"no feature enables the optional dependency `{crate}` (`dep:{crate}`)")
        for feature in sorted(behind[crate]):
            if feature == "default":
                continue
            if feature not in features:
                report(f"feature `{feature}` of `{crate}` is missing")
            elif not {f"{crate}?/{feature}", f"{crate}/{feature}"} & set(features[feature]):
                report(f"feature `{feature}` does not enable `{crate}?/{feature}`")

    for feature in sorted(features):
        for item in features[feature]:
            crate, slash, target = item.partition("/")
            weak = crate.endswith("?")
            crate = crate.removesuffix("?")
            if not slash or crate not in behind:
                continue
            if crate in optional and not weak:
                if f"dep:{crate}" not in _reachable(features, feature):
                    report(
                        f"feature `{feature}` enables `{item}`, which pulls in the "
                        f"optional `{crate}`: use `{crate}?/{target}`"
                    )
            if crate == CORE and target in NOT_OFFERED:
                report(f"feature `{feature}` enables `{item}`, which `NOT_OFFERED` names")
            elif target != feature:
                report(f"feature `{feature}` enables `{item}`, a feature of another name")

    default = set(features.get("default", []))
    expected = set()
    for crate, table in behind.items():
        crate_default = set(table.get("default", []))
        expected |= crate_default
        for feature in sorted(crate_default - default):
            report(f"default feature `{feature}` of `{crate}` is not a default feature")
    for feature in sorted(default - expected):
        report(f"default feature `{feature}` is not a default feature of a crate behind the facade")
    for feature in sorted(default):
        for crate in optional:
            if f"dep:{crate}" in {feature} | _reachable(features, feature):
                report(f"default feature `{feature}` enables the optional dependency `{crate}`")

    return sorted(diagnostics)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(__doc__ or "").split("\n\n", maxsplit=1)[0]
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root (defaults to the script's repository)",
    )
    args = parser.parse_args(argv)
    try:
        diagnostics = check(args.repo_root.resolve())
    except (OSError, UnicodeError, ValueError) as error:
        print(f"facade feature check could not start: {error}", file=sys.stderr)
        return 2
    if diagnostics:
        for diagnostic in diagnostics:
            print(diagnostic.render(), file=sys.stderr)
        print(
            f"facade feature check failed with {len(diagnostics)} error(s)",
            file=sys.stderr,
        )
        return 1
    print(f"validated the features of `{FACADE}` against the crates behind it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
