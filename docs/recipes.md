# Recipe reference

Recipes are JSON objects with version `1`, optional lifecycle hooks and an ordered list of built-in steps.

```json
{
  "version": 1,
  "preflight": {
    "command": ["host-check", "--non-invasive"],
    "environment": {}
  },
  "pre_run": {
    "command": ["ownership-tool", "acquire"],
    "environment": {}
  },
  "post_run": {
    "command": ["ownership-tool", "restore"],
    "environment": {}
  },
  "steps": [
    {
      "kind": "mark",
      "arguments": {
        "label": "change-setting"
      }
    }
  ]
}
```

Hook commands are argument arrays executed without a shell.  Hook environments cannot replace `IOS_BLE_CAPTURE_RUN_ID` or `IOS_BLE_CAPTURE_RUN_DIR`.

The optional `preflight` hook performs link-independent checks before the `pre_run` ownership handoff.  The post-run hook executes exactly once after any attempted run, including pre-run failure, run failure and handled interruption.  A failed preflight does not invoke ownership hooks.

`run --dry-run` validates the recipe and lists step kinds without executing hooks, starting processes, driving WebDriverAgent, compiling schemas, sleeping or writing run files.

## Steps

| Kind | Required arguments | Optional arguments |
| --- | --- | --- |
| `assert` | `file`, `equals` | none |
| `capture` | `udid`, `host`, `output` | none |
| `decode` | `target_path`, `ksy_root`, `root_schema`, `module_name`, `root_type_name`, `compiler`, exactly one of `data_hex` or `data_file` | `cache_directory`, `import_paths`, `output` |
| `diff` | `before`, `after` | `output` |
| `launch` | `wda_url`, `bundle_id` | none |
| `mark` | `label` | `timestamp`, `output` |
| `report` | none | `events`, `include_identifiers`, `include_raw`, `output` |
| `screenshot` | `wda_url`, `bundle_id` | `output` |
| `swipe` | `wda_url`, `bundle_id`, `name`, `start`, `end` | none |
| `tap` | `wda_url`, `bundle_id`, `name` | none |
| `type` | `wda_url`, `bundle_id`, `name`, `text` | none |
| `wait` | `seconds` | none |

Paths used for target schemas and decode input are resolved relative to the recipe.  Run outputs are direct children of the private run directory; directory traversal is refused.

`swipe` drags across one exact displayed named element using fractional `start` and `end` positions from `0` to `1`.  Named WebDriverAgent actions refuse ambiguous, missing and non-displayed elements.

The recipe format contains no inline Python, inline shell or plugin import.  A generally useful operation belongs in the package as a built-in step.
