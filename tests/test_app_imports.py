def test_application_imports() -> None:
    import app.main  # noqa: F401
    import app.api.settings  # noqa: F401
    import app.fofa.router  # noqa: F401
