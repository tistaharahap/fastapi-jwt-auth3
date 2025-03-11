from typing import Any, Dict, Optional, Set, Type, TypeVar, Union

# Detect Pydantic version
try:
    import pydantic

    PYDANTIC_V2 = int(pydantic.__version__.split(".")[0]) >= 2
except (ImportError, AttributeError, IndexError):
    # Fallback method
    try:
        from pydantic import field_validator

        PYDANTIC_V2 = True
    except ImportError:
        PYDANTIC_V2 = False

# Import common components
from pydantic import BaseModel

# TypeVar for type hints
ModelT = TypeVar("ModelT", bound=BaseModel)

# Import version-specific components
if PYDANTIC_V2:
    from pydantic import ConfigDict, field_validator, field_serializer

    # Use v2's field_validator as validator
    validator = field_validator

    def model_dump(
        model: BaseModel,
        exclude_none: bool = False,
        exclude_unset: bool = False,
        exclude: Optional[Union[Set[str], Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Use model_dump in v2"""
        return model.model_dump(
            exclude_none=exclude_none,
            exclude_unset=exclude_unset,
            exclude=exclude,
        )

    def model_validate(
        model_class: Type[ModelT],
        obj: Dict[str, Any],
    ) -> ModelT:
        """Use model_validate in v2"""
        return model_class.model_validate(obj)

    def configure_model(cls: Type[BaseModel], **config_values):
        """Set model_config in v2"""
        cls.model_config = ConfigDict(**config_values)

else:
    # For Pydantic v1

    # Create a ConfigDict placeholder for v1
    class ConfigDict(dict):
        """Placeholder for compatibility"""

        pass

    # Dummy field_serializer for v1
    def field_serializer(*args, **kwargs):
        """Dummy decorator for v1"""

        def decorator(func):
            return func

        return decorator

    def model_dump(
        model: BaseModel,
        exclude_none: bool = False,
        exclude_unset: bool = False,
        exclude: Optional[Union[Set[str], Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Use dict in v1"""
        return model.dict(
            exclude_none=exclude_none,
            exclude_unset=exclude_unset,
            exclude=exclude,
        )

    def model_validate(
        model_class: Type[ModelT],
        obj: Dict[str, Any],
    ) -> ModelT:
        """Use parse_obj in v1"""
        return model_class.parse_obj(obj)

    def configure_model(cls: Type[BaseModel], **config_values):
        """Set Config class in v1"""
        config_class = getattr(cls, "Config", type("Config", (), {}))
        for key, value in config_values.items():
            setattr(config_class, key, value)
        cls.Config = config_class
