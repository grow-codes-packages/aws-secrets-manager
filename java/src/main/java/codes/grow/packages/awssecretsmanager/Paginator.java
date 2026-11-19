package codes.grow.packages.awssecretsmanager;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * Lazily walks every page of an AWS list operation ({@code ListSecrets}, {@code
 * ListSecretVersionIds}). Iterate with a for-each loop, use {@link #stream()}, or collect
 * everything with {@link #toList()}. Each iteration starts again from the first page; a page is
 * fetched only when the previous one is consumed.
 *
 * @param <T> item type
 */
public final class Paginator<T> implements Iterable<T> {
  /**
   * One fetched page.
   *
   * @param items items of the page
   * @param nextToken token of the next page, or {@code null} on the last page
   * @param <T> item type
   */
  public record Page<T>(List<T> items, String nextToken) {
    /** Copies the items. */
    public Page {
      items = List.copyOf(items);
    }
  }

  private final Function<String, Page<T>> fetch;

  /**
   * Creates a paginator.
   *
   * @param fetch fetches one page for a token ({@code null} for the first page)
   */
  public Paginator(Function<String, Page<T>> fetch) {
    this.fetch = fetch;
  }

  /**
   * Returns the pages (one list per page).
   *
   * @return a lazy iterable of pages
   */
  public Iterable<List<T>> pages() {
    return PageIterator::new;
  }

  @Override
  public Iterator<T> iterator() {
    Iterator<List<T>> pages = pages().iterator();
    return new Iterator<>() {
      private Iterator<T> current = List.<T>of().iterator();

      @Override
      public boolean hasNext() {
        while (!current.hasNext()) {
          if (!pages.hasNext()) {
            return false;
          }
          current = pages.next().iterator();
        }
        return true;
      }

      @Override
      public T next() {
        if (!hasNext()) {
          throw new NoSuchElementException();
        }
        return current.next();
      }
    };
  }

  /**
   * Returns a sequential stream of every item.
   *
   * @return the stream
   */
  public Stream<T> stream() {
    return StreamSupport.stream(spliterator(), false);
  }

  /**
   * Collects every item of every page.
   *
   * @return the items
   */
  public List<T> toList() {
    List<T> out = new ArrayList<>();
    for (List<T> page : pages()) {
      out.addAll(page);
    }
    return out;
  }

  private final class PageIterator implements Iterator<List<T>> {
    private final Set<String> seen = new HashSet<>();
    private String token;
    private boolean done;

    @Override
    public boolean hasNext() {
      return !done;
    }

    @Override
    public List<T> next() {
      if (done) {
        throw new NoSuchElementException();
      }
      Page<T> page = fetch.apply(token);
      token = page.nextToken();
      // A token that is absent, empty or repeated ends the walk (Moto sends "" and null).
      if (token == null || token.isEmpty() || !seen.add(token)) {
        done = true;
      }
      return page.items();
    }
  }
}
