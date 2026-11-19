//! Lazy auto-pagination over AWS `NextToken` pages.

use std::collections::VecDeque;
use std::fmt;

use futures::future::BoxFuture;
use futures::Stream;

use crate::core::Result;

/// One page: items and the next token (`None` = last page).
pub(crate) type Page<T> = (Vec<T>, Option<String>);

type Fetch<T> = Box<dyn FnMut(Option<String>) -> BoxFuture<'static, Result<Page<T>>> + Send>;

/// Lazy iterator over every page of a list call. Nothing is sent until the first
/// [`next`](Paginator::next), [`next_page`](Paginator::next_page) or
/// [`try_collect`](Paginator::try_collect).
pub struct Paginator<T> {
    fetch: Fetch<T>,
    token: Option<String>,
    started: bool,
    done: bool,
    buffer: VecDeque<T>,
}

impl<T> fmt::Debug for Paginator<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Paginator")
            .field("started", &self.started)
            .field("done", &self.done)
            .field("buffered", &self.buffer.len())
            .finish()
    }
}

impl<T: Send + 'static> Paginator<T> {
    pub(crate) fn new<F>(fetch: F) -> Self
    where
        F: FnMut(Option<String>) -> BoxFuture<'static, Result<Page<T>>> + Send + 'static,
    {
        Paginator {
            fetch: Box::new(fetch),
            token: None,
            started: false,
            done: false,
            buffer: VecDeque::new(),
        }
    }

    /// The next page of items (`None` after the last page). Items already handed out by
    /// [`next`](Paginator::next) are not repeated.
    pub async fn next_page(&mut self) -> Result<Option<Vec<T>>> {
        if !self.buffer.is_empty() {
            return Ok(Some(self.buffer.drain(..).collect()));
        }
        if self.done {
            return Ok(None);
        }
        let token = if self.started {
            self.token.take()
        } else {
            None
        };
        self.started = true;
        let (items, next) = (self.fetch)(token).await?;
        self.done = next.is_none();
        self.token = next;
        Ok(Some(items))
    }

    /// The next item (`None` at the end).
    pub async fn next(&mut self) -> Result<Option<T>> {
        loop {
            if let Some(item) = self.buffer.pop_front() {
                return Ok(Some(item));
            }
            match self.next_page().await? {
                None => return Ok(None),
                Some(items) => self.buffer.extend(items),
            }
        }
    }

    /// Every remaining item of every page.
    pub async fn try_collect(mut self) -> Result<Vec<T>> {
        let mut out = Vec::new();
        while let Some(page) = self.next_page().await? {
            out.extend(page);
        }
        Ok(out)
    }

    /// The items as a [`Stream`].
    pub fn into_stream(self) -> impl Stream<Item = Result<T>> + Send {
        futures::stream::unfold(self, |mut p| async move {
            match p.next().await {
                Ok(Some(item)) => Some((Ok(item), p)),
                Ok(None) => None,
                Err(e) => {
                    p.done = true;
                    p.buffer.clear();
                    Some((Err(e), p))
                }
            }
        })
    }
}
