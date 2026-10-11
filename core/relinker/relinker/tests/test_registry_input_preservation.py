import os
from pathlib import Path
import subprocess
import sys
import tempfile

from test_guest_intel_trampolines import PLAIN_SITE, guest_fixture, main_fixture


def link(source, target, alias):
    if alias == "hardlink":
        os.link(source, target)
    else:
        try:
            target.symlink_to(source)
        except OSError as error:
            if os.name != "nt" or error.winerror != 1314:
                raise
            print("Symbolic-link case skipped: Windows symlink privilege unavailable")
            return False
    return True


def main():
    relinker = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="anyps5-registry-preservation-") as directory:
        work = Path(directory)
        for windows in (False, True):
            options = ["--windows"] if windows else []
            for guest_registry in (False, True):
                registry_name = "output.sample.prx.guest.prx.registry.json" if guest_registry else "output.registry.json"
                for bundled in (False, True):
                    for alias in ("direct", "normalized", "hardlink", "symlink"):
                        case = work / f"{windows}-{guest_registry}-{bundled}-{alias}"
                        case.mkdir()
                        modules = case / "sce_module"
                        modules.mkdir()
                        sample = modules / "sample.prx"
                        sample.write_bytes(guest_fixture(PLAIN_SITE))
                        output_directory = modules if bundled else case
                        registry = output_directory / registry_name
                        source = case / "input.elf"
                        if bundled:
                            source.write_bytes(main_fixture())
                            protected = registry if alias in ("direct", "normalized") else modules / "protected.prx"
                            protected.write_bytes(guest_fixture(PLAIN_SITE))
                        else:
                            source = registry if alias in ("direct", "normalized") else source
                            source.write_bytes(main_fixture())
                            protected = source
                        if alias in ("hardlink", "symlink") and not link(protected, registry, alias):
                            continue
                        if alias == "normalized":
                            (output_directory / "unused").mkdir()
                            output_directory = output_directory / "unused" / ".."
                        output = output_directory / ("output.exe" if windows else "output.elf")
                        original = source.read_bytes()
                        module_original = protected.read_bytes()
                        sample_original = sample.read_bytes()
                        arguments = ["--skip-sce-module"] if not guest_registry and not bundled else []
                        result = subprocess.run([str(relinker), *options, *arguments, "--registry", str(source), str(output)],
                                                capture_output=True, text=True, timeout=20)
                        if (result.returncode != 2
                                or "Registry output would overwrite an input file:" not in result.stderr
                                or source.read_bytes() != original
                                or protected.read_bytes() != module_original
                                or registry.read_bytes() != module_original
                                or sample.read_bytes() != sample_original
                                or output.exists()
                                or (output.parent / "app0").exists()
                                or sorted(path.resolve() for path in output.parent.glob("*.registry.json")) != [registry.resolve()]):
                            raise AssertionError((windows, guest_registry, bundled, alias,
                                                  result.returncode, result.stdout, result.stderr))

            for guest_output in (False, True):
                for alias in ("hardlink", "symlink"):
                    case = work / f"{windows}-output-{guest_output}-{alias}"
                    case.mkdir()
                    source = case / "input.elf"
                    source.write_bytes(main_fixture())
                    modules = case / "sce_module"
                    modules.mkdir()
                    sample = modules / "sample.prx"
                    sample.write_bytes(guest_fixture(PLAIN_SITE))
                    output = case / ("output.exe" if windows else "output.elf")
                    protected = case / "app0" / "sce_module" / "sample.prx.guest.prx" if guest_output else output
                    protected.parent.mkdir(parents=True, exist_ok=True)
                    protected.write_bytes(b"previous output")
                    registry = case / "output.registry.json"
                    if not link(protected, registry, alias):
                        continue
                    result = subprocess.run([str(relinker), *options, "--registry", str(source), str(output)],
                                            capture_output=True, text=True, timeout=20)
                    if (result.returncode != 2
                            or "Registry output collides with another output:" not in result.stderr
                            or protected.read_bytes() != b"previous output"
                            or registry.read_bytes() != b"previous output"
                            or source.read_bytes() != main_fixture()
                            or sample.read_bytes() != guest_fixture(PLAIN_SITE)
                            or sorted(case.glob("*.registry.json")) != [registry]):
                        raise AssertionError((windows, guest_output, alias,
                                              result.returncode, result.stdout, result.stderr))

            for existing in (False, True):
                case = work / f"{windows}-registry-alias-{existing}"
                case.mkdir()
                source = case / "input.elf"
                source.write_bytes(main_fixture())
                modules = case / "sce_module"
                modules.mkdir()
                sample = modules / "sample.prx"
                sample.write_bytes(guest_fixture(PLAIN_SITE))
                registry = case / "output.registry.json"
                module_registry = case / "output.sample.prx.guest.prx.registry.json"
                if existing:
                    module_registry.write_bytes(b"previous registry")
                if not link(module_registry, registry, "symlink"):
                    continue
                output = case / ("output.exe" if windows else "output.elf")
                result = subprocess.run([str(relinker), *options, "--registry", str(source), str(output)],
                                        capture_output=True, text=True, timeout=20)
                rejected = "Registry output collides with another output:" in result.stderr
                if os.name == "nt" and not existing:
                    rejected |= "Cannot verify registry output path: " + str(registry) + ":" in result.stderr
                if (result.returncode != 2
                        or not rejected
                        or output.exists() or (case / "app0").exists()
                        or source.read_bytes() != main_fixture()
                        or sample.read_bytes() != guest_fixture(PLAIN_SITE)
                        or (existing and module_registry.read_bytes() != b"previous registry")
                        or (not existing and module_registry.exists())):
                    raise AssertionError((windows, existing, result.returncode, result.stdout, result.stderr))
    print("Registry input preservation tests passed")


if __name__ == "__main__":
    main()
