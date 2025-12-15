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
```

Set environment variables:

```bash
export MAILARCHIVE_API_KEY=__api_key__
export MAILARCHIVE_BASE_URL=https://mailarchive.ietf.org/arch/
export MAILARCHIVE_DESTINATION=https://mailarchive.ietf.org/api/v1/message/import/
```

## License

GPLv3+
