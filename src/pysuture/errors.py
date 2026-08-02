class PySutureError(RuntimeError):
    """Expected user-facing PySuture failure."""


class ConfigurationError(PySutureError):
    pass


class AnalysisError(PySutureError):
    pass


class LockError(PySutureError):
    pass


class BuildError(PySutureError):
    pass
