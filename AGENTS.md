# Repository workflow

- Maintain `CHANGELOG.md` for user-visible changes. Record additions, fixes,
  changed behavior, and any migration steps.
- Complete changes with an appropriate version bump and release when authorized
  by the task. Keep the Lake version, `LeanWs.packageVersion`, README install
  tag, changelog section, and Git tag consistent.
- Follow `RELEASING.md` for validation and publication. Run `lake test` before
  releasing; it requires local socket access.
- Keep the library pure Lean: no C bindings and no external libraries. Build on
  `Std.Http`'s types and parsers and on `Std.Async` rather than duplicating them.
- Protocol behavior follows RFC 6455. When a rule is enforced, name the close
  code it produces in the doc comment and cover it in the `session` test suite
  with hand-built frames.
- Use Lean's expressive types to encode meaningful domain rules: inductive
  alternatives, typed close codes and errors, and validated values. Keep
  wire-format bytes at serialization boundaries.
