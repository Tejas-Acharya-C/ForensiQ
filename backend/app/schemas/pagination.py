"""Standardized pagination schema and query parameters for ForensiQ."""

from typing import Generic, List, TypeVar, Optional
from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic bounded paginated response container."""
    items: List[T] = Field(..., description="List of items for current page")
    total: int = Field(..., ge=0, description="Total number of matching accessible records")
    limit: int = Field(..., ge=1, le=500, description="Page size limit")
    offset: int = Field(..., ge=0, description="Page offset")
    has_more: bool = Field(..., description="Whether additional records exist beyond current page")
