def test_application_imports() -> None:
    import app.main  # noqa: F401
    import app.api.gateway_hunt  # noqa: F401
    import app.api.settings  # noqa: F401
    import app.fofa.router  # noqa: F401
    import app.gateway_hunt.client  # noqa: F401
    import app.gateway_hunt.profiles.litellm  # noqa: F401
