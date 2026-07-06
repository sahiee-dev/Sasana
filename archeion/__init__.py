# Archeion — Sasana authority sealing server.


def run() -> None:
    """Entry point for the `archeion` CLI command."""
    try:
        from archeion.server import run as _run
    except ModuleNotFoundError as exc:
        raise SystemExit(
            f"archeion: missing dependency ({exc.name}). Install with: pip install sasana[archeion]"
        ) from exc
    _run()
