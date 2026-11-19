package codes.grow.packages.awssecretsmanager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class PaginatorTest {
  @Test
  void walksPagesLazilyAndStopsOnRepeatedOrEmptyTokens() {
    AtomicInteger calls = new AtomicInteger();
    Paginator<Integer> p =
        new Paginator<>(
            token -> {
              calls.incrementAndGet();
              if (token == null) {
                return new Paginator.Page<>(List.of(1, 2), "a");
              }
              if (token.equals("a")) {
                return new Paginator.Page<>(List.of(), "b");
              }
              return new Paginator.Page<>(List.of(3), "a"); // repeats "a": stop
            });
    Iterator<Integer> it = p.iterator();
    assertThat(calls.get()).isZero();
    assertThat(it.next()).isEqualTo(1);
    assertThat(calls.get()).isEqualTo(1);
    assertThat(p.toList()).containsExactly(1, 2, 3);
    assertThat(p.stream().mapToInt(Integer::intValue).sum()).isEqualTo(6);
    Iterator<List<Integer>> pages = p.pages().iterator();
    pages.next();
    pages.next();
    pages.next();
    assertThat(pages.hasNext()).isFalse();
    assertThatThrownBy(pages::next).isInstanceOf(NoSuchElementException.class);
    Iterator<Integer> empty =
        new Paginator<Integer>(t -> new Paginator.Page<>(List.of(), "")).iterator();
    assertThat(empty.hasNext()).isFalse();
    assertThatThrownBy(empty::next).isInstanceOf(NoSuchElementException.class);
  }
}
