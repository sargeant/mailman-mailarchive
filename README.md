# mailman-mailarchive

Mailman 3 archiver plugin for IETF Mail Archive.

## Installation

```bash
pip install git+https://github.com/ietf-tools/mailman-mailarchive.git
```

## Configuration

Add to `mailman.cfg`:

```ini
[archiver.ietf_mailarchive]
class: mailman_mailarchive.IETFMailarchive
enable: yes
configuration: /etc/mailman3/ietf_mailarchive.cfg
```

Create the configuration file (e.g., `/etc/mailman3/ietf_mailarchive.cfg`):

```ini
[general]
base_url: https://mailarchive.ietf.org/arch/
api_key: your_api_key_here
destination: https://mailarchive.ietf.org/api/v1/message/import/
```

## Configuration Options

| Option | Description |
|--------|-------------|
| `base_url` | Base URL for archive links (used in `Archived-At` header) |
| `api_key` | Authentication key for Mail Archive API |
| `destination` | API endpoint URL |

## License

GPLv3+
