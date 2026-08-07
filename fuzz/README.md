# Coverage-guided fuzzing

Veil keeps dependency-free mutation smoke tests in normal CI and also ships
Atheris entry points for longer coverage-guided runs.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[fuzz]'
python fuzz/fuzz_framing.py -max_total_time=60
python fuzz/fuzz_invite.py -max_total_time=60
python fuzz/fuzz_event.py -max_total_time=60
python fuzz/fuzz_noise.py -max_total_time=60
```

Crashes should be minimized and added as regression cases under `tests/`.
Do not treat a fuzz run that finds no crashes as a security audit.
