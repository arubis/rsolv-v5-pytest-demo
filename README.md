# rsolv-v5-pytest-demo

A deliberately vulnerable, standard-library-only Python project (one SQL injection in
`app/users.py`) used to exercise the RSOLV v5 pipeline end to end on staging:
scan → validate (RED test) → mitigate (fix) → verify (RED/GREEN in a sandbox) → publish.

Do not use this code.
