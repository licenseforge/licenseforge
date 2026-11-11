package io.licenseforge.sdk;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.UnaryOperator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Protection against the system clock being turned back (ADR-0018), as the Go
 * SDK's clock package: a high-water mark of the latest trusted time.
 * {@link Guard#now} returns max(local, mark), the time to check licenses with;
 * a local clock more than the tolerance behind the mark is a rollback.
 *
 * <p>The mark is raised by now itself and by observe (a license iat that passed
 * its checks, capped at local + tolerance), and set by reset (a verified
 * lease's iat after an online refresh: the only way to lower it). The stored
 * mark is authenticated with HMAC-SHA256 under a key derived from the license
 * key; state that fails it, is corrupt or unreadable counts as no state, like
 * deleted state (within the threat model, ADR-0014; max_offline bounds the
 * gain). Offline recovery from a rollback, after fixing the clock: delete the
 * state file.
 */
public final class Clock {
  private Clock() {}

  public static final Duration DEFAULT_TOLERANCE = Duration.ofHours(24);
  /** The longest tolerance accepted; more would overflow Instant arithmetic. */
  public static final Duration MAX_TOLERANCE = Duration.ofDays(36500);
  /** The smallest mark increase worth writing: no fsync on every check. */
  private static final Duration PERSIST_EVERY = Duration.ofMinutes(1);

  /**
   * ROLLBACK: the local clock is too far behind the last trusted time: fix it,
   * refresh online, or (offline) delete the state. The check always runs:
   * unreadable state counts as none.
   */
  public static final class ClockException extends Exception {
    private static final long serialVersionUID = 1L;

    public enum Code {
      ROLLBACK
    }

    private final Code code;

    ClockException(Code code, String detail) {
      super("licenseforge clock: " + detail);
      this.code = code;
    }

    public Code code() {
      return code;
    }
  }

  /**
   * Persists a guard's state. update calls fn with the current state (null for
   * none, or when it can't be read) and writes what fn returns (null: no
   * change). It returns false when the state couldn't be read or the result
   * couldn't be written; fn is called either way.
   */
  public interface Store {
    boolean update(UnaryOperator<byte[]> fn);
  }

  /** The result of a check: the time to use, and whether the new mark was saved. */
  public record Now(Instant now, boolean persisted) {}

  /** Tracks the high-water mark for one license. Safe for concurrent use. */
  public static final class Guard {
    private final Store store;
    private final byte[] key;
    private final Duration tolerance;

    /** A guard with the default tolerance (24 h). */
    public Guard(Store store, String licenseKey) {
      this(store, licenseKey, DEFAULT_TOLERANCE);
    }

    /** A guard for one license, its state in store, authenticated with a key derived from licenseKey. */
    public Guard(Store store, String licenseKey, Duration tolerance) {
      this.store = Objects.requireNonNull(store, "store");
      Objects.requireNonNull(licenseKey, "licenseKey");
      Objects.requireNonNull(tolerance, "tolerance");
      if (licenseKey.isEmpty()) throw new IllegalArgumentException("licenseforge clock: empty license key");
      if (tolerance.isNegative() || tolerance.compareTo(MAX_TOLERANCE) > 0) throw new IllegalArgumentException("licenseforge clock: tolerance must be between 0 and 36500 days");
      this.tolerance = tolerance;
      // SHA-256 rather than HKDF, as the Go SDK: FIPS modes refuse short HKDF inputs.
      this.key = sha256(("licenseforge clock v1|" + licenseKey).getBytes(StandardCharsets.UTF_8));
    }

    private byte[] mac(String mark) {
      try {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(key, "HmacSHA256"));
        return m.doFinal(("v1|" + mark).getBytes(StandardCharsets.UTF_8));
      } catch (GeneralSecurityException e) {
        throw new IllegalStateException(e);
      }
    }

    /** The stored mark, or null for no state (empty, corrupt, or failing the MAC). */
    private Instant decode(byte[] b) {
      if (b == null || b.length == 0) return null;
      try {
        if (!(Json.parseValue(KeySet.utf8(b)) instanceof Map<?, ?> m)) return null;
        if (!(m.get("mark") instanceof String mark) || !(m.get("mac") instanceof String mac)) return null;
        if (!MessageDigest.isEqual(Base64.getDecoder().decode(mac), mac(mark))) return null;
        return Instant.parse(mark);
      } catch (Json.JsonException | IOException | IllegalArgumentException | java.time.DateTimeException e) {
        return null;
      }
    }

    private byte[] encode(Instant t) {
      String mark = t.toString(); // ISO-8601 UTC; the MAC covers this exact text
      return ("{\"mark\":\"" + mark + "\",\"mac\":\"" + Base64.getEncoder().encodeToString(mac(mark)) + "\"}").getBytes(StandardCharsets.UTF_8);
    }

    /** The time to check licenses with, given the system clock. Throws ROLLBACK. */
    public synchronized Now now(Instant local) throws ClockException {
      Objects.requireNonNull(local, "local");
      Instant[] now = {local};
      boolean[] rollback = {false};
      boolean[] ran = {false};
      boolean persisted = store.update(cur -> {
        ran[0] = true;
        Instant mark = decode(cur);
        // Overflow-free (a mark near Instant.MIN or MAX): local is more than the tolerance behind the mark.
        if (mark != null && Duration.between(local, mark).compareTo(tolerance) > 0) {
          rollback[0] = true;
          return null;
        }
        if (mark != null && mark.isAfter(local)) now[0] = mark;
        return mark == null || Duration.between(mark, local).compareTo(PERSIST_EVERY) >= 0 ? encode(local) : null;
      });
      // A store that never runs the check is broken: fail closed, as the Go SDK does.
      if (!ran[0]) throw new IllegalStateException("licenseforge clock: the store didn't run the check");
      if (rollback[0]) {
        throw new ClockException(ClockException.Code.ROLLBACK,
            "system clock is behind the last trusted time; fix the clock, refresh the license online, or (offline) delete the clock state");
      }
      return new Now(now[0], persisted);
    }

    /** {@link #now(Instant)} with the system clock. */
    public Now now() throws ClockException {
      return now(Instant.now());
    }

    /**
     * Raises the mark to t, a time known to be genuine (the iat of a license
     * that passed its checks); capped at local + tolerance, so a fast vendor
     * clock can't lock out an honest user. Returns whether it was saved.
     */
    public synchronized boolean observe(Instant t, Instant local) {
      Instant capped = t.isAfter(local.plus(tolerance)) ? local.plus(tolerance) : t;
      return store.update(cur -> {
        Instant mark = decode(cur);
        return mark == null || capped.isAfter(mark) ? encode(capped) : null;
      });
    }

    /**
     * Sets the mark to serverTime after a successful online refresh, even
     * lower: the online way out of a rollback. serverTime must be
     * authenticated (a verified lease's iat), never an HTTP Date header.
     */
    public synchronized boolean reset(Instant serverTime) {
      Objects.requireNonNull(serverTime, "serverTime");
      return store.update(cur -> encode(serverTime));
    }
  }

  private static byte[] sha256(byte[] b) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(b);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Keeps the mark in memory: it resets on every restart, so use a file for offline licenses. */
  public static final class MemoryStore implements Store {
    private byte[] state;

    @Override
    public synchronized boolean update(UnaryOperator<byte[]> fn) {
      byte[] next = fn.apply(state == null ? null : state.clone());
      if (next != null) state = next.clone();
      return true;
    }
  }

  /**
   * Keeps the state in a file. Updates are serialized across processes with
   * an OS lock on path + ".lock" (released if the process dies) and within
   * this JVM per path; written atomically: a temp file (mode 0600 where the
   * filesystem has POSIX permissions) in the same directory, fsync, rename,
   * fsync of the directory. If another process holds the lock for 2 s, the
   * write is skipped (not persisted); if locking is unavailable (read-only
   * directory, network filesystem) the write is attempted without it, since
   * rename is atomic. A missing file is no state; an unreadable one counts as
   * none and is reported as not persisted. The OS lock is POSIX (fcntl) on
   * Unix: it serializes Java processes, not a Go SDK process (flock) sharing
   * the same file.
   */
  public static final class FileStore implements Store {
    private static final Duration LOCK_WAIT = Duration.ofSeconds(2);
    // ponytail: one monitor for every FileStore in this JVM. Per path, two paths to one file
    // (a symlink, a bind mount, case) would overlap, and closing one channel drops the
    // process's fcntl lock for both. Contention is negligible (one short update per check);
    // the cost: another process holding one file's lock delays checks on other files up to 2 s.
    private static final Object LOCK = new Object();
    private final Path path;

    public FileStore(Path path) {
      this.path = Objects.requireNonNull(path, "path").toAbsolutePath().normalize();
    }

    @Override
    public boolean update(UnaryOperator<byte[]> fn) {
      // In this JVM too: the OS lock may be unavailable (then only this serializes).
      synchronized (LOCK) {
        FileChannel lockFile = null;
        FileLock lock = null;
        boolean held = false; // another process holds the lock: skip the write
        try {
          lockFile = openLock(Path.of(path + ".lock"));
          long deadline = System.nanoTime() + LOCK_WAIT.toNanos();
          while ((lock = tryLock(lockFile)) == null) {
            if (System.nanoTime() > deadline) {
              held = true;
              break;
            }
            Thread.sleep(10);
          }
        } catch (IOException e) {
          // locking unavailable: go on without it
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          held = true;
        }
        try {
          byte[] cur = null;
          boolean readable = true;
          try {
            cur = Files.readAllBytes(path);
          } catch (NoSuchFileException e) {
            // no state
          } catch (IOException e) {
            readable = false; // counts as no state; reported as not persisted
          }
          byte[] next = fn.apply(cur);
          if (next == null) return readable;
          if (held) return false;
          try {
            write(next);
            return readable;
          } catch (IOException e) {
            return false;
          }
        } finally {
          try {
            if (lock != null) lock.release();
            if (lockFile != null) lockFile.close();
          } catch (IOException ignored) {
            // released when the process exits anyway
          }
        }
      }
    }

    private static FileChannel openLock(Path p) throws IOException {
      try {
        return FileChannel.open(p, java.util.Set.of(StandardOpenOption.CREATE, StandardOpenOption.WRITE),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
      } catch (UnsupportedOperationException e) {
        return FileChannel.open(p, StandardOpenOption.CREATE, StandardOpenOption.WRITE); // no POSIX permissions (Windows)
      }
    }

    private static FileLock tryLock(FileChannel ch) throws IOException {
      try {
        return ch.tryLock();
      } catch (OverlappingFileLockException e) {
        return null; // held in this JVM (another FileStore object): wait
      }
    }

    private void write(byte[] b) throws IOException {
      Path dir = path.getParent();
      Path tmp = dir.resolve(".licenseforge-clock-" + UUID.randomUUID());
      try {
        try {
          Files.createFile(tmp, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } catch (UnsupportedOperationException e) {
          Files.createFile(tmp); // no POSIX permissions here (Windows)
        }
        try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.WRITE)) {
          ByteBuffer buf = ByteBuffer.wrap(b);
          while (buf.hasRemaining()) ch.write(buf);
          ch.force(true);
        }
        // On Windows the rename fails while another program (antivirus,
        // backup) has the target open: retry briefly, as the Go SDK does.
        for (int attempt = 0; ; attempt++) {
          try {
            Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            break;
          } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING);
            break;
          } catch (IOException e) {
            if (attempt == 4 || Files.isDirectory(path)) throw e;
            try {
              Thread.sleep(20);
            } catch (InterruptedException ie) {
              Thread.currentThread().interrupt();
              throw e;
            }
          }
        }
      } catch (IOException | RuntimeException e) {
        Files.deleteIfExists(tmp); // a failed write leaves no temp file
        throw e;
      }
      try (FileChannel d = FileChannel.open(dir, StandardOpenOption.READ)) {
        d.force(true); // make the rename durable; not possible on Windows
      } catch (IOException e) {
        // the filesystem handles it there
      }
    }
  }
}
