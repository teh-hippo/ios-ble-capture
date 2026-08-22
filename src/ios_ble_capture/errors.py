class CaptureError(Exception):
    """Base error for expected capture-tool failures."""


class CaptureDataError(CaptureError, ValueError):
    """Raised when capture data violates a public data contract."""


class HookExecutionError(CaptureError):
    """Raised when a lifecycle hook exits unsuccessfully."""


class PostHookError(HookExecutionError):
    """Raised when ownership restoration fails."""


class RecipeError(CaptureDataError):
    """Raised when a recipe violates the declarative recipe contract."""


class RunInterruptedError(CaptureError):
    """Raised when an active run receives an interrupt signal."""
