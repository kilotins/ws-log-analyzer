# Streamlit UI Patterns for WS Log Analyzer

## Architecture

`app.py` is the Streamlit GUI. It is a thin UI layer that imports all logic from `wslog.py`.
Never add parsing, analysis, or prompt-building logic to `app.py`.

## Session State Conventions

- All state keys are defined in `_STATE_DEFAULTS` dict at the top of `app.py`
- Use `snake_case` for all keys: `claude_answer`, `rt_enabled`, `swedish_chef`
- Initialize with `for key, default in _STATE_DEFAULTS.items()` loop
- Never access a session state key without first ensuring it has a default

## Button Callbacks (Critical)

**Always use `on_click` callbacks, never `st.form` inside expanders.**

Streamlit reruns the entire script on every interaction. `st.form_submit_button` inside
expanders has known issues where clicks don't register. The reliable pattern:

```python
def _on_button_click():
    st.session_state._pending_action = True

st.button("Do thing", on_click=_on_button_click)

if st.session_state.pop("_pending_action", False):
    # Execute the action here
    ...
```

## Widget `value=` vs `key=`

After the first render, a widget with `key="my_key"` ignores the `value=` parameter.
To programmatically update a widget's value, set `st.session_state.my_key` directly
in a callback — never pass `value=` expecting it to override.

## Expanders

- Use `expanded=True` for sections the user needs to see immediately
- Hide sections with 0 items (e.g., "Likely Causes (0 detected)" should not render)
- Content inside collapsed expanders is in the DOM but not visible — use
  `.scroll_into_view_if_needed()` in tests

## Realtime Updates

Use `@st.fragment(run_every=N)` for polling without full app rerun.
Keep fragments small — they re-execute independently of the main script.

## HTML Components

Use `st.components.v1.html()` for browser-side features (audio playback, etc.).
Embed data as base64 data URIs to avoid serving static files.
Set explicit `height=` to avoid iframe sizing issues.

## File Structure

```
app.py          — All Streamlit UI code
assets/chef/    — Swedish Chef sound clips and image
logs/app.log    — Rotating application log (gitignored)
cache/          — Claude response cache (gitignored)
reports/        — Generated reports (gitignored)
uploads/        — Uploaded files (gitignored)
```
