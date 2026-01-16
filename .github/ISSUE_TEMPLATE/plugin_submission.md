---
name: Plugin Submission
about: Submit a new custom check/plugin for the community
title: '[PLUGIN] '
labels: plugin
assignees: ''
---

## Plugin Information

| Field | Value |
|-------|-------|
| **Plugin Name** | |
| **Version** | 1.0.0 |
| **Author** | @your-github-username |
| **Category** | Security / Accessibility / Performance / Compliance |

## Description

A clear and concise description of what your plugin does.

## Use Case

Explain the problem this plugin solves and who would benefit from it.

## Features

- [ ] Feature 1
- [ ] Feature 2
- [ ] Feature 3

## Example Output

```json
{
  "type": "custom-check",
  "name": "your-check-name",
  "severity": "high",
  "message": "Example finding message",
  "details": {}
}
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `option1` | string | `""` | Description |
| `option2` | boolean | `false` | Description |

## Dependencies

List any npm packages or external services required:

- `package-name@version`
- External API: [service name]

## Testing

Describe how you've tested the plugin:

- [ ] Unit tests included
- [ ] Tested against real targets
- [ ] Tested in different environments

## Documentation

- [ ] README included with usage instructions
- [ ] Code comments/JSDoc added
- [ ] Example configuration provided

## Checklist

- [ ] I have read the [Plugin Development Guide](../../custom_checks/README.md)
- [ ] My plugin follows the standard interface
- [ ] I have not included any malicious code
- [ ] This plugin does not perform active exploitation
- [ ] I agree to the MIT license for this contribution

## Additional Notes

Any other information about your plugin.
