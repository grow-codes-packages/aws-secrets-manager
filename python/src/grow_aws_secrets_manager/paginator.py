"""Auto-paginating iterators for the AWS list operations (sync and async)."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from typing import Generic, TypeVar

__all__ = ["Paginator", "AsyncPaginator", "PageFetcher", "AsyncPageFetcher"]

T = TypeVar("T")

#: Fetches one page: ``fetch(next_token) -> (items, next_token or None)``.
PageFetcher = Callable[[str | None], tuple[list[T], str | None]]
#: Async :data:`PageFetcher`.
AsyncPageFetcher = Callable[[str | None], Awaitable[tuple[list[T], str | None]]]


class Paginator(Generic[T]):
    """Lazily walks every page of an AWS list operation.

    Iterate it (``for item in client.list_secrets()``), walk :meth:`pages`, or collect everything
    with :meth:`to_list`. Every iteration starts again from the first page.
    """

    def __init__(self, fetch: PageFetcher[T]) -> None:
        self._fetch = fetch

    def pages(self) -> Iterator[list[T]]:
        """Yields one list per page."""
        token: str | None = None
        seen: set[str] = set()
        while True:
            items, token = self._fetch(token)
            yield items
            # Defensive: a service that repeats a token would loop forever.
            if token is None or token in seen:
                return
            seen.add(token)

    def __iter__(self) -> Iterator[T]:
        for page in self.pages():
            yield from page

    def to_list(self) -> list[T]:
        """Every item of every page."""
        return list(self)


class AsyncPaginator(Generic[T]):
    """Async :class:`Paginator`: ``async for item in client.list_secrets()`` or
    ``await client.list_secrets().to_list()``."""

    def __init__(self, fetch: AsyncPageFetcher[T]) -> None:
        self._fetch = fetch

    async def pages(self) -> AsyncIterator[list[T]]:
        """Yields one list per page."""
        token: str | None = None
        seen: set[str] = set()
        while True:
            items, token = await self._fetch(token)
            yield items
            if token is None or token in seen:
                return
            seen.add(token)

    async def __aiter__(self) -> AsyncIterator[T]:
        async for page in self.pages():
            for item in page:
                yield item

    async def to_list(self) -> list[T]:
        """Every item of every page."""
        return [item async for item in self]
