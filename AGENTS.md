# Notes for AI Coding Assistants

## Repository overview

A SpamAssassin plugin (single Perl module `AI/AI.pm`) that sends email
text to an OpenAI-compatible LLM endpoint and scores the message based
on the AI verdict (SPAM/HAM/UNSURE).

Four files total: `AI.pre` (plugin loader + rule definitions),
`AI.cf` (user-facing config + scores), `AI/AI.pm` (plugin code),
and `README.md`.

## File encoding

`AI/AI.pm` is **iso-8859-1**, not UTF-8.  Comments are in Ukrainian
using Latin-extended characters.  Tools that assume UTF-8 will fail
to read or edit the file -- use `cat`, `sed`, or `perl` via the
terminal instead.

## SpamAssassin plugin API

- `$class->SUPER::new($mailsa)` already calls `bless`; do not
  call `bless` again.
- Access the message object via `$pms->get_message()`, **not**
  `$pms->{msg}`.
- `$pms->got_hit($rule)` is for activating named rules defined in
  config (e.g. `AI_SPAM`, `AI_HAM`).  Do not use it for error
  signaling -- just `return (0)` and set a tag instead.
- Use `//` (defined-or) rather than `||` for config defaults, so
  that `0` or `''` values from config are not silently overridden.

## Configuration files

`AI.pre` and `AI.cf` use SpamAssassin's config DSL (`loadplugin`,
`header`, `meta`, `describe`, `score`, `add_header`, and custom
directives registered via `parse_config`).  They are not free-form
config files.

Custom directives recognized by this plugin: `ai_url`, `ai_max_size`,
`ai_timeout`, `ai_user_agent`, `ai_api_key`, `ai_language`.

## Coding style

Follow BSD `style(9)` conventions where applicable to Perl:

- Tab indentation.
- 4 spaces for continuation lines.
- Blanks around operators and `=` signs.
- No braces around simple one-statement `if`/`else` branches.
  (Perl requires braces on block-form `if`, so this applies only
  to postfix guards like `return (0) if $cond;` — do **not**
  rewrite braced `if` blocks into postfix form for readability.)
- Single quotes for strings unless interpolation or escape
  sequences are needed.

## Testing

There is no local test harness.  `perl -c AI/AI.pm` will fail
because `Mail::SpamAssassin::Plugin` and its dependencies are not
available outside a SpamAssassin installation.  Verify syntax only
(e.g. stub out the `use` lines, or check with a regex/AST linter).
