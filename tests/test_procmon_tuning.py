from pkgprobe_trace.procmon_tuning import parse_procmon_tuning


def test_procmon_tuning_defaults_balanced():
    t = parse_procmon_tuning("balanced", "")
    assert t.profile == "balanced"
    assert t.baseline_subtraction is True
    assert t.strict_pid_tree is False
    assert t.include_processes == []


def test_procmon_tuning_low_noise_defaults():
    t = parse_procmon_tuning("low_noise", "")
    assert t.profile == "low_noise"
    assert t.baseline_subtraction is True
    assert t.strict_pid_tree is True


def test_procmon_tuning_json_override():
    t = parse_procmon_tuning(
        "high_fidelity",
        '{"exclude_processes":["vmtoolsd.exe"],"registry_only":true,"baseline_subtraction":true}',
    )
    assert t.profile == "high_fidelity"
    assert t.exclude_processes == ["vmtoolsd.exe"]
    assert t.registry_only is True
    assert t.baseline_subtraction is True
