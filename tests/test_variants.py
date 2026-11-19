"""Android build variants (context/variants.py) and the build_variants / read_config tools."""

from __future__ import annotations

from pathlib import Path

from gapscan.agent.tools import ToolBox
from gapscan.context.variants import describe, find_modules, variant_names, variants_including

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "eval" / "fixtures" / "android-flavors"

GROOVY = """apply plugin: 'com.android.application'
android {
    flavorDimensions "tier"
    productFlavors {
        free { dimension "tier"; buildConfigField "boolean", "PRO", "false" }
        paid {
            dimension "tier"
            buildConfigField "boolean", "PRO", "true"
        }
    }
    buildTypes {
        release {
            minifyEnabled true
        }
        staging {
            debuggable true
        }
    }
}
"""


def test_kotlin_dsl_flavors_build_types_and_settings():
    (mod,) = find_modules(FIXTURE)
    assert [f.name for f in mod.flavors] == ["dev", "prod"]
    assert {t.name for t in mod.build_types} == {"release", "debug"}
    assert sorted(variant_names(mod)) == ["devDebug", "devRelease", "prodDebug", "prodRelease"]
    dev = mod.flavors[0]
    assert any('"ENCRYPT_DB", "false"' in text for _, text in dev.settings)


def test_which_variants_ship_a_file():
    (mod,) = find_modules(FIXTURE)
    main = "app/src/main/java/com/example/notes/db/DatabaseKeyManager.kt"
    assert len(variants_including(mod, main) or []) == 4
    dev = "app/src/dev/res/xml/network_security_config.xml"
    assert sorted(variants_including(mod, dev) or []) == ["devDebug", "devRelease"]
    assert variants_including(mod, "app/src/test/x.kt") == []
    assert variants_including(mod, "README.md") is None


def test_groovy_dsl_and_custom_build_types(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "build.gradle").write_text(GROOVY)
    (mod,) = find_modules(tmp_path)
    assert [f.name for f in mod.flavors] == ["free", "paid"]
    assert {t.name for t in mod.build_types} == {"release", "staging", "debug"}
    assert "paidStaging" in variant_names(mod)
    assert variants_including(mod, "app/src/paidRelease/x.kt") == ["paidRelease"]


def test_non_android_projects_say_so(tmp_path):
    (tmp_path / "build.gradle.kts").write_text('plugins { kotlin("jvm") }\n')
    text, seen = describe(tmp_path)
    assert "no Android Gradle module" in text and seen == []


def test_build_variants_tool_marks_the_gradle_lines_it_quotes():
    r = ToolBox(FIXTURE).execute(
        "build_variants", {"file": "app/src/dev/res/xml/network_security_config.xml"}
    )
    assert r.ok and "is built into: devRelease, devDebug" in r.text
    assert ("app/build.gradle.kts", 21, 21) in r.seen  # dev's ENCRYPT_DB = false
    assert not ToolBox(FIXTURE).execute("build_variants", {"file": "../outside.txt"}).ok


def test_read_config_returns_numbered_setting_lines():
    tb = ToolBox(FIXTURE)
    r = tb.execute("read_config", {"file": "app/src/dev/res/xml/network_security_config.xml",
                                   "key": "cleartextTrafficPermitted"})  # fmt: skip
    assert r.ok and "4 | " in r.text and 'cleartextTrafficPermitted="true"' in r.text
    assert r.seen == [("app/src/dev/res/xml/network_security_config.xml", 4, 4)]
    missing = tb.execute(
        "read_config", {"file": "app/src/main/AndroidManifest.xml", "key": "usesCleartextTraffic"}
    )
    assert missing.ok and missing.outcome == "not_set"
    assert not tb.execute("read_config", {"file": "app/build.gradle.kts", "key": "a b; rm"}).ok


def test_triage_context_lists_shipping_variants_and_the_flags_the_code_checks():
    from gapscan.context.extract import build_context
    from gapscan.models import Category, Finding, Severity

    def ctx(file, line, cat):
        f = Finding(scanner="x", rule_id="r", title="t", severity=Severity.HIGH, category=cat,
                    file=file, start_line=line, end_line=line)  # fmt: skip
        return build_context(f, FIXTURE)

    key = ctx("app/src/main/java/com/example/notes/db/DatabaseKeyManager.kt", 7, Category.SECRET)
    assert "built into: devRelease, devDebug, prodRelease, prodDebug" in key.variants[0]
    assert any("flavor dev sets ENCRYPT_DB" in v and '"false"' in v for v in key.variants)
    assert "BUILD VARIANTS" in key.render()
    dev = ctx("app/src/dev/res/xml/network_security_config.xml", 4, Category.CONFIG)
    assert dev.variants == [
        "app/src/dev/res/xml/network_security_config.xml is built into: devRelease, devDebug "
        "(not into: prodRelease, prodDebug)"
    ]


def test_a_secret_in_a_shipped_source_set_is_packaged_in_the_app():
    from gapscan.models import Category, Finding, Severity
    from gapscan.secret_facts import annotate_secrets

    def secret(file, line):
        return Finding(scanner="gitleaks", rule_id="generic-api-key", title="t",
                       severity=Severity.HIGH, category=Category.SECRET, file=file,
                       start_line=line, end_line=line)  # fmt: skip

    (f,) = annotate_secrets(
        [secret("app/src/main/java/com/example/notes/db/DatabaseKeyManager.kt", 7)], FIXTURE
    )
    facts = f.raw["secret_facts"]
    assert facts["shipped_in_app"] and len(facts["shipped_variants"]) == 4
    (g,) = annotate_secrets([secret("README.md", 1)], FIXTURE)
    assert not g.raw["secret_facts"]["shipped_in_app"]
