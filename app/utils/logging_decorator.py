import logging
import functools
import inspect

logger = logging.getLogger("app")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

def logging_decorator(func):
    if inspect.iscoroutinefunction(func):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            logger.info(f"Called async function: {func.__name__}")
            try:
                result = await func(*args, **kwargs)
                logger.info(f"Function: {func.__name__} returned: {result}")
                return result
            except Exception as e:
                logger.exception(f"Error in function {func.__name__} : {e}")
                raise
        return async_wrapper
    else:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            logger.info(f"Called Function: {func.__name__}")
            try:
                result = func(*args, **kwargs)
                logger.info(f"Function: {func.__name__} Returned: {result}")
                return result
            except Exception as e:
                logger.exception(f"Error in Function {func.__name__}: {e} ")
                raise
        return wrapper
