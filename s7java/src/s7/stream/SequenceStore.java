// SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package s7.stream;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;

import s7.wire.WireFormat;

/** Durable sequence-range reservations (wire draft section 4): a producer never reuses a sequence number. */
public interface SequenceStore {
    /** End of the last reservation for the stream (0 if none). */
    long reservedEnd(byte[] streamId);

    /** Durably records a new reservation end; returns only once it is safe. */
    void reserve(byte[] streamId, long end);

    final class Memory implements SequenceStore {
        private final Map<String, Long> ends = new HashMap<>();

        @Override
        public synchronized long reservedEnd(byte[] streamId) {
            return ends.getOrDefault(WireFormat.streamIdText(streamId), 0L);
        }

        @Override
        public synchronized void reserve(byte[] streamId, long end) {
            ends.put(WireFormat.streamIdText(streamId), end);
        }
    }

    /**
     * The C++ node's format: {@code <directory>/<stream_id>.seq} holding the reservation end in
     * decimal and a newline, written to a temporary file, fsync'ed and renamed.
     */
    final class FileStore implements SequenceStore {
        private final Path directory;

        public FileStore(Path directory) {
            this.directory = directory;
            try {
                Files.createDirectories(directory);
            } catch (IOException ex) {
                throw new UncheckedIOException(ex);
            }
        }

        private Path path(byte[] streamId) {
            return directory.resolve(WireFormat.streamIdText(streamId) + ".seq");
        }

        @Override
        public long reservedEnd(byte[] streamId) {
            Path path = path(streamId);
            if (!Files.exists(path)) {
                return 0;
            }
            try {
                String text = Files.readString(path).strip();
                if (!text.matches("[0-9]+")) {
                    throw new IllegalStateException("Corrupt sequence reservation for stream " + WireFormat.streamIdText(streamId) + ".");
                }
                return Long.parseUnsignedLong(text);
            } catch (IOException ex) {
                throw new UncheckedIOException(ex);
            }
        }

        @Override
        public void reserve(byte[] streamId, long end) {
            Path path = path(streamId);
            Path temporary = path.resolveSibling(path.getFileName() + ".tmp");
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                channel.write(java.nio.ByteBuffer.wrap((Long.toUnsignedString(end) + "\n").getBytes(StandardCharsets.US_ASCII)));
                channel.force(true);
            } catch (IOException ex) {
                throw new UncheckedIOException(ex);
            }
            try {
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException ex) {
                throw new UncheckedIOException(ex);
            }
        }
    }
}
