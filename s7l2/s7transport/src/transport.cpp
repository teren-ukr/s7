// SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "s7/transport.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <exception>
#include <filesystem>
#include <future>
#include <iterator>
#include <map>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include <boost/asio/connect.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace s7::transport {
namespace {

[[nodiscard]] auto normalize_ws_base_target(std::string target) -> std::string
{
    if (target.empty() || target == "/") {
        return {};
    }
    if (target.ends_with("/control")) {
        target.resize(target.size() - std::strlen("/control"));
    } else if (target.ends_with("/data")) {
        target.resize(target.size() - std::strlen("/data"));
    }
    if (target == "/") {
        return {};
    }
    return target;
}

[[nodiscard]] auto ws_target_for_path(const ParsedWebSocketUrl& parsed, const std::string_view suffix) -> std::string
{
    const auto base = normalize_ws_base_target(parsed.target);
    if (base.empty()) {
        return std::string(suffix);
    }
    return base + std::string(suffix);
}

[[nodiscard]] auto peer_certificate_from_x509(X509* certificate) -> PeerCertificate
{
    PeerCertificate info;

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (X509_digest(certificate, EVP_sha256(), digest, &digest_len) != 1) {
        throw std::runtime_error("Failed to compute certificate fingerprint.");
    }
    static constexpr char hex[] = "0123456789abcdef";
    for (unsigned int index = 0; index < digest_len; ++index) {
        info.fingerprint_sha256.push_back(hex[digest[index] >> 4]);
        info.fingerprint_sha256.push_back(hex[digest[index] & 0x0F]);
    }

    const auto names_deleter = [](GENERAL_NAMES* names) { GENERAL_NAMES_free(names); };
    std::unique_ptr<GENERAL_NAMES, decltype(names_deleter)> names(
        static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(certificate, NID_subject_alt_name, nullptr, nullptr)),
        names_deleter);
    for (int index = 0; names && index < sk_GENERAL_NAME_num(names.get()); ++index) {
        const GENERAL_NAME* name = sk_GENERAL_NAME_value(names.get(), index);
        if (name->type == GEN_URI) {
            const ASN1_IA5STRING* uri = name->d.uniformResourceIdentifier;
            info.uri_sans.emplace_back(reinterpret_cast<const char*>(ASN1_STRING_get0_data(uri)),
                                       static_cast<std::size_t>(ASN1_STRING_length(uri)));
        }
    }

    const auto usages_deleter = [](EXTENDED_KEY_USAGE* usages) { EXTENDED_KEY_USAGE_free(usages); };
    std::unique_ptr<EXTENDED_KEY_USAGE, decltype(usages_deleter)> usages(
        static_cast<EXTENDED_KEY_USAGE*>(X509_get_ext_d2i(certificate, NID_ext_key_usage, nullptr, nullptr)),
        usages_deleter);
    for (int index = 0; usages && index < sk_ASN1_OBJECT_num(usages.get()); ++index) {
        char oid[128];
        const int length = OBJ_obj2txt(oid, sizeof(oid), sk_ASN1_OBJECT_value(usages.get(), index), 1);
        if (length > 0 && static_cast<std::size_t>(length) < sizeof(oid)) {
            info.key_purpose_oids.emplace_back(oid, static_cast<std::size_t>(length));
        }
    }
    return info;
}

// The verified client certificate of a TLS session, if any.
[[nodiscard]] auto verified_peer_certificate(SSL* ssl) -> std::optional<PeerCertificate>
{
    std::unique_ptr<X509, decltype(&X509_free)> certificate(SSL_get1_peer_certificate(ssl), X509_free);
    if (!certificate || SSL_get_verify_result(ssl) != X509_V_OK) {
        return std::nullopt;
    }
    return peer_certificate_from_x509(certificate.get());
}

} // namespace

auto verified_peer_certificate_of(void* openssl_ssl) -> std::optional<PeerCertificate>
{
    return verified_peer_certificate(static_cast<SSL*>(openssl_ssl));
}

auto node_uuid_of(const PeerCertificate& certificate) -> std::optional<std::string>
{
    constexpr std::string_view prefix = "spiffe://s7/node/";
    std::optional<std::string> found;
    for (const auto& uri : certificate.uri_sans) {
        if (uri.starts_with(prefix)) {
            if (found) {
                return std::nullopt; // more than one node identity
            }
            found = uri.substr(prefix.size());
        }
    }
    return found;
}

auto check_node_identity(const std::optional<PeerCertificate>& certificate, const std::string_view claimed_node_uuid) -> NodeIdentity
{
    if (!certificate) {
        return NodeIdentity::Unverified;
    }
    const auto uuid = node_uuid_of(*certificate);
    return uuid && !claimed_node_uuid.empty() && *uuid == claimed_node_uuid ? NodeIdentity::Verified : NodeIdentity::Mismatch;
}

auto to_string(const NodeIdentity identity) -> std::string
{
    switch (identity) {
        case NodeIdentity::Verified: return "verified";
        case NodeIdentity::Unverified: return "unverified";
        case NodeIdentity::Mismatch: return "identity_mismatch";
    }
    return "unverified";
}

auto inspect_certificate_file(const std::string& pem_path) -> PeerCertificate
{
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_file(pem_path.c_str(), "r"), BIO_free);
    if (!bio) {
        throw std::runtime_error("Could not open certificate: '" + pem_path + "'.");
    }
    std::unique_ptr<X509, decltype(&X509_free)> certificate(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free);
    if (!certificate) {
        throw std::runtime_error("Could not parse PEM certificate: '" + pem_path + "'.");
    }
    return peer_certificate_from_x509(certificate.get());
}

auto parse_ws_url(const std::string& url) -> ParsedWebSocketUrl
{
    ParsedWebSocketUrl parsed;
    std::size_t host_start = 0;
    if (url.rfind("ws://", 0) == 0) {
        parsed.secure = false;
        host_start = std::strlen("ws://");
    } else if (url.rfind("wss://", 0) == 0) {
        parsed.secure = true;
        host_start = std::strlen("wss://");
    } else {
        throw std::invalid_argument("Only ws:// and wss:// URLs are supported: '" + url + "'.");
    }
    const auto path_pos = url.find('/', host_start);
    const auto host_port = path_pos == std::string::npos ? url.substr(host_start) : url.substr(host_start, path_pos - host_start);

    const auto colon_pos = host_port.rfind(':');
    if (colon_pos == std::string::npos || colon_pos == 0 || colon_pos + 1 >= host_port.size()) {
        throw std::invalid_argument("WebSocket URL must include host:port: '" + url + "'.");
    }

    parsed.host = host_port.substr(0, colon_pos);
    if (parsed.host.starts_with('[') && parsed.host.ends_with(']')) {
        parsed.host = parsed.host.substr(1, parsed.host.size() - 2);
    } else if (parsed.host.find(':') != std::string::npos) {
        throw std::invalid_argument("IPv6 WebSocket addresses must be bracketed: '" + url + "'.");
    }
    parsed.port = host_port.substr(colon_pos + 1);
    parsed.target = path_pos == std::string::npos ? "/" : url.substr(path_pos);
    return parsed;
}

// ============================================================================
// Stream table: the streams of one endpoint and the blocking graph-side API.
// One mutex guards every StreamProducer / StreamConsumer; the transport's I/O
// thread and the graph threads both take it, and nothing else touches the
// stream objects.
// ============================================================================
namespace {

using stream::Clock;
using stream::FaultCode;

struct StreamEntry {
    StreamHandle handle;
    StreamRole role{StreamRole::Producer};
    stream::StreamConfig config;
    std::unique_ptr<stream::StreamProducer> producer;
    std::unique_ptr<stream::StreamConsumer> consumer;
    bool open{true}; // owned by an element; a closed stream keeps its state
    std::uint64_t unauthorized{}; // see StreamStatus::unauthorized
    std::deque<RecentFault> recent_faults;
    FaultCode noted{FaultCode::None}; // the stream fault already in recent_faults
    Clock::time_point late_noted{};    // LATE goes to recent_faults at most once a second

    // After a packet arrived late (lock held).
    void note_late()
    {
        const auto now = Clock::now();
        if (now - late_noted < std::chrono::seconds(1)) {
            return;
        }
        late_noted = now;
        const auto latency = consumer->latency();
        note(FaultCode::Late, "latency_ms=" + std::to_string(latency.last_ns / 1'000'000) +
                                  " max_latency_ms=" + std::to_string(config.max_latency ? config.max_latency->count() : 0));
    }

    [[nodiscard]] FaultCode fault_code() const { return producer ? producer->fault_code() : consumer->fault_code(); }

    void note(const FaultCode code, std::string detail)
    {
        if (recent_faults.size() == kMaxRecentFaults) {
            recent_faults.pop_front();
        }
        recent_faults.push_back(RecentFault{code, std::move(detail), std::chrono::system_clock::now()});
    }
    // Records the stream's fault once, when it is first seen.
    void note_fault()
    {
        const auto code = fault_code();
        if (code != FaultCode::None && code != noted) {
            note(code, {});
        }
        noted = code;
    }
};

std::string stream_key(const wire::StreamId& id)
{
    return std::string(reinterpret_cast<const char*>(id.data()), id.size());
}

class StreamTable {
public:
    // Called with the lock held after producer data or consumer progress changed,
    // so the transport can send (posts work; must not block).
    std::function<void(StreamEntry&)> on_producer_data;
    std::function<void(StreamEntry&)> on_consumer_opened;
    // After the graph took elements (lock held): an in-memory consumer acknowledges.
    std::function<void(StreamEntry&)> on_consumed;

    explicit StreamTable(stream::SequenceStore& sequences) : sequences_(sequences) {}

    // Reopening a closed stream of the same type continues it (a redeployed
    // graph takes over the stream without loss); another type starts anew.
    StreamHandle open(const stream::StreamConfig& config, const StreamRole role)
    {
        std::unique_lock lock(mutex);
        auto& index = role == StreamRole::Producer ? producers_ : consumers_;
        if (const auto it = index.find(stream_key(config.stream_id)); it != index.end()) {
            auto& existing = *entries_.at(it->second);
            if (existing.open) {
                throw std::invalid_argument("Stream " + wire::to_string(config.stream_id) + " is already open as " +
                                            (role == StreamRole::Producer ? "producer" : "consumer") + ".");
            }
            if (existing.config.type == config.type) {
                existing.open = true;
                existing.config.max_block = config.max_block;
                existing.config.max_wait = config.max_wait;
                existing.config.producer_node = config.producer_node;
                existing.config.consumer_nodes = config.consumer_nodes;
                existing.config.max_latency = config.max_latency;
                changed.notify_all();
                return existing.handle;
            }
            entries_.erase(it->second);
            index.erase(it);
        }
        auto entry = std::make_unique<StreamEntry>();
        entry->handle = StreamHandle{next_handle_++};
        entry->role = role;
        entry->config = config;
        if (role == StreamRole::Producer) {
            entry->producer = std::make_unique<stream::StreamProducer>(config, sequences_);
            entry->producer->set_stamp_send_time(clock_usable_);
        } else {
            // The alias is the handle: unique among this endpoint's consumer streams.
            entry->consumer = std::make_unique<stream::StreamConsumer>(config, static_cast<std::uint32_t>(entry->handle.value));
        }
        const auto handle = entry->handle;
        index[stream_key(config.stream_id)] = handle.value;
        auto& stored = *entries_.emplace(handle.value, std::move(entry)).first->second;
        if (role == StreamRole::Consumer && on_consumer_opened) {
            on_consumer_opened(stored);
        }
        if (role == StreamRole::Producer && on_producer_data) {
            on_producer_data(stored); // apply RESUMEs that arrived before the producer opened
        }
        return handle;
    }

    void close(const StreamHandle handle)
    {
        std::unique_lock lock(mutex);
        const auto it = entries_.find(handle.value);
        if (it == entries_.end()) {
            return;
        }
        it->second->open = false;
        changed.notify_all();
    }

    PublishResult publish(const StreamHandle handle, const void* elements, const std::size_t count,
                          const std::span<const wire::TimestampRecord> times)
    {
        std::unique_lock lock(mutex);
        auto& entry = require(handle, StreamRole::Producer);
        auto& producer = *entry.producer;
        const auto element_bytes = signal_type_info(entry.config.type).storage_bytes;
        const auto* bytes = static_cast<const std::uint8_t*>(elements);
        std::size_t done = 0;
        std::optional<Clock::time_point> deadline;
        while (done < count) {
            if (producer.fault_code() != FaultCode::None) {
                return {count, producer.fault_code()}; // a faulted stream drops data; the graph continues
            }
            const auto now = Clock::now();
            done += producer.append(bytes + done * element_bytes, count - done, now, times);
            if (on_producer_data) {
                on_producer_data(entry);
            }
            if (done == count) {
                break;
            }
            // Backpressure: wait for acknowledgements, up to max_block.
            if (!deadline) {
                deadline = now + entry.config.max_block;
            }
            const auto wait_start = Clock::now();
            const bool room = changed.wait_until(lock, *deadline, [&] {
                return !entries_.contains(handle.value) || !producer.log_full() || producer.fault_code() != FaultCode::None;
            });
            if (!entries_.contains(handle.value)) {
                return {done, FaultCode::None};
            }
            producer.add_blocked_time(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - wait_start));
            if (!room) {
                producer.fault(FaultCode::SendLogOverflow);
                return {done, FaultCode::SendLogOverflow};
            }
        }
        return {count, FaultCode::None};
    }

    // `starving` is called (lock held) when a receive has to wait: the in-memory
    // endpoint flushes partial batches there.
    ReceiveResult receive(const StreamHandle handle, void* elements, const std::size_t count,
                          const std::function<void(StreamEntry&)>& starving = {})
    {
        std::unique_lock lock(mutex);
        auto& entry = require(handle, StreamRole::Consumer);
        auto& consumer = *entry.consumer;
        const auto element_bytes = signal_type_info(entry.config.type).storage_bytes;
        auto* bytes = static_cast<std::uint8_t*>(elements);
        std::size_t taken = 0;
        const auto deadline = Clock::now() + entry.config.max_wait;
        std::vector<wire::TimestampRecord> first_times;
        while (true) {
            const auto before = taken;
            taken += consumer.take(bytes + taken * element_bytes, count - taken, taken == 0 ? &first_times : nullptr);
            if (taken > before && on_consumed) {
                on_consumed(entry);
            }
            if (taken == count || consumer.fault_code() != FaultCode::None) {
                break;
            }
            if (starving) {
                starving(entry);
                taken += consumer.take(bytes + taken * element_bytes, count - taken, taken == 0 ? &first_times : nullptr);
                if (taken == count) {
                    break;
                }
            }
            const bool data = changed.wait_until(lock, deadline, [&] {
                return !entries_.contains(handle.value) || consumer.available() > 0 || consumer.fault_code() != FaultCode::None;
            });
            if (!entries_.contains(handle.value)) {
                return {taken, FaultCode::None, std::move(first_times)};
            }
            if (!data) {
                consumer.fault(FaultCode::Underrun);
                break;
            }
        }
        return {taken, consumer.fault_code(), std::move(first_times)};
    }

    [[nodiscard]] std::vector<StreamStatus> statuses()
    {
        std::unique_lock lock(mutex);
        std::vector<StreamStatus> result;
        for (const auto& [_, entry] : entries_) {
            StreamStatus status;
            status.stream_id = entry->config.stream_id;
            status.role = entry->role;
            status.type = entry->config.type;
            status.unauthorized = entry->unauthorized;
            entry->note_fault();
            status.recent_faults.assign(entry->recent_faults.begin(), entry->recent_faults.end());
            if (entry->producer) {
                const auto stats = entry->producer->stats();
                status.fault = entry->producer->fault_code();
                status.next_sequence = entry->producer->next_sequence();
                status.packets = stats.packets;
                status.elements = stats.elements;
                status.replayed = stats.replayed;
                status.lost_resumes = stats.lost_resumes;
                status.send_log_depth = stats.send_log_depth;
                status.blocked_total = stats.blocked_total;
                status.state = status.fault != FaultCode::None ? "faulted"
                               : !entry->open                  ? "closed"
                               : entry->producer->log_full()   ? "blocked"
                                                               : "active";
            } else {
                const auto stats = entry->consumer->stats();
                status.elements = stats.elements;
                status.fault = entry->consumer->fault_code();
                status.next_sequence = stats.next_expected;
                status.packets = stats.packets;
                status.duplicates_discarded = stats.duplicates_discarded;
                status.malformed = stats.malformed;
                status.buffered_elements = stats.buffered_elements;
                status.latency = entry->consumer->latency();
                status.state = status.fault != FaultCode::None ? "faulted" : entry->open ? "active" : "closed";
            }
            result.push_back(std::move(status));
        }
        return result;
    }

    bool recover(const wire::StreamId& id)
    {
        std::unique_lock lock(mutex);
        bool found = false;
        for (auto* index : {&producers_, &consumers_}) {
            if (const auto it = index->find(stream_key(id)); it != index->end()) {
                auto& entry = *entries_.at(it->second);
                entry.note_fault();
                if (entry.producer) {
                    entry.producer->recover();
                } else {
                    entry.consumer->recover();
                }
                found = true;
            }
        }
        changed.notify_all();
        return found;
    }

    void set_clock_usable(const bool usable)
    {
        std::lock_guard lock(mutex);
        clock_usable_ = usable;
        for (auto& [_, entry] : entries_) {
            if (entry->producer) {
                entry->producer->set_stamp_send_time(usable);
            }
        }
    }

    void note_all(const FaultCode code, const std::string& detail)
    {
        std::lock_guard lock(mutex);
        for (auto& [_, entry] : entries_) {
            entry->note(code, detail);
        }
    }

    // Lock held by the caller.
    StreamEntry* find(const StreamHandle handle)
    {
        const auto it = entries_.find(handle.value);
        return it == entries_.end() ? nullptr : it->second.get();
    }
    StreamEntry* find_producer(const wire::StreamId& id)
    {
        const auto it = producers_.find(stream_key(id));
        return it == producers_.end() ? nullptr : entries_.at(it->second).get();
    }
    StreamEntry* find_consumer(const wire::StreamId& id)
    {
        const auto it = consumers_.find(stream_key(id));
        return it == consumers_.end() ? nullptr : entries_.at(it->second).get();
    }
    StreamEntry* find_consumer_by_alias(const std::uint32_t alias)
    {
        auto* entry = find(StreamHandle{alias});
        return entry && entry->role == StreamRole::Consumer ? entry : nullptr;
    }
    template <typename F>
    void for_each(F&& f)
    {
        for (auto& [_, entry] : entries_) {
            f(*entry);
        }
    }

    mutable std::mutex mutex;
    std::condition_variable changed;

private:
    StreamEntry& require(const StreamHandle handle, const StreamRole role)
    {
        const auto it = entries_.find(handle.value);
        if (it == entries_.end() || it->second->role != role) {
            throw std::invalid_argument(std::string("Not an open ") + (role == StreamRole::Producer ? "producer" : "consumer") + " stream.");
        }
        return *it->second;
    }

    stream::SequenceStore& sequences_;
    bool clock_usable_{true};
    std::uint64_t next_handle_{1};
    std::unordered_map<std::uint64_t, std::unique_ptr<StreamEntry>> entries_;
    std::unordered_map<std::string, std::uint64_t> producers_;
    std::unordered_map<std::string, std::uint64_t> consumers_;
};

} // namespace

// ============================================================================
// In-memory endpoint: producer and consumer of a stream in one process.
// ============================================================================

struct InMemoryRuntimeNetEndpoint::Impl {
    stream::MemorySequenceStore sequences;
    StreamTable table{sequences};

    // Lock held. Moves everything the producer has to the local consumer.
    void transfer(const wire::StreamId& id)
    {
        auto* producer = table.find_producer(id);
        auto* consumer = table.find_consumer(id);
        if (!producer || !consumer) {
            return;
        }
        static const std::string key = "local";
        const auto now = Clock::now();
        if (!attached.contains(stream_key(id))) {
            const auto resume = consumer->consumer->resume_message();
            producer->producer->resume(key, resume.stream_alias, resume.next_expected);
            attached.insert(stream_key(id));
        }
        while (auto message = producer->producer->next_message(key)) {
            if (consumer->consumer->on_packet(wire::decode_data_packet(*message), now)) {
                consumer->note_late();
            }
        }
        // The local consumer acknowledges whatever the graph has taken.
        if (const auto ack = consumer->consumer->ack_due(now + stream::kAckInterval)) {
            producer->producer->acknowledge(key, ack->next_expected);
        }
        table.changed.notify_all();
    }

    std::unordered_set<std::string> attached;
};

InMemoryRuntimeNetEndpoint::InMemoryRuntimeNetEndpoint() : impl_(std::make_unique<Impl>())
{
    auto* impl = impl_.get();
    impl->table.on_producer_data = [impl](StreamEntry& entry) {
        // Within one process there is nothing to batch for: seal at once.
        entry.producer->flush(Clock::now(), true);
        impl->transfer(entry.config.stream_id);
    };
    impl->table.on_consumer_opened = [impl](StreamEntry& entry) { impl->transfer(entry.config.stream_id); };
    impl->table.on_consumed = [impl](StreamEntry& entry) { impl->transfer(entry.config.stream_id); };
}

InMemoryRuntimeNetEndpoint::~InMemoryRuntimeNetEndpoint() = default;

auto InMemoryRuntimeNetEndpoint::backend_name() const -> std::string
{
    return "inmemory";
}

auto InMemoryRuntimeNetEndpoint::open_producer(const stream::StreamConfig& config) -> StreamHandle
{
    return impl_->table.open(config, StreamRole::Producer);
}

auto InMemoryRuntimeNetEndpoint::open_consumer(const stream::StreamConfig& config) -> StreamHandle
{
    return impl_->table.open(config, StreamRole::Consumer);
}

void InMemoryRuntimeNetEndpoint::close_stream(const StreamHandle handle)
{
    impl_->table.close(handle);
}

auto InMemoryRuntimeNetEndpoint::publish(const StreamHandle handle, const void* elements, const std::size_t count,
                                   const std::span<const wire::TimestampRecord> times) -> PublishResult
{
    return impl_->table.publish(handle, elements, count, times);
}

auto InMemoryRuntimeNetEndpoint::receive(const StreamHandle handle, void* elements, const std::size_t count) -> ReceiveResult
{
    auto* impl = impl_.get();
    return impl->table.receive(handle, elements, count, [impl](StreamEntry& entry) {
        // A waiting consumer: flush the producer's partial batch now and acknowledge.
        if (auto* producer = impl->table.find_producer(entry.config.stream_id)) {
            producer->producer->flush(Clock::now(), true);
        }
        impl->transfer(entry.config.stream_id);
    });
}

auto InMemoryRuntimeNetEndpoint::stream_statuses() const -> std::vector<StreamStatus>
{
    return impl_->table.statuses();
}

void InMemoryRuntimeNetEndpoint::set_clock_usable(const bool usable)
{
    impl_->table.set_clock_usable(usable);
}

void InMemoryRuntimeNetEndpoint::note_on_all_streams(const stream::FaultCode code, const std::string& detail)
{
    impl_->table.note_all(code, detail);
}

auto InMemoryRuntimeNetEndpoint::recover_stream(const wire::StreamId& stream_id) -> bool
{
    return impl_->table.recover(stream_id);
}

// ============================================================================
// WebSocket endpoint: one I/O thread runs every socket operation
// asynchronously; control requests run on a separate worker thread.
// ============================================================================

namespace {

using Tcp = boost::asio::ip::tcp;
namespace websocket = boost::beast::websocket;
namespace http = boost::beast::http;
namespace ssl = boost::asio::ssl;
using PlainWs = websocket::stream<boost::beast::tcp_stream>;
using TlsWs = websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>>;
using Bytes = std::vector<std::uint8_t>;

constexpr std::size_t kMaxQueuedWrites = 64; // per connection, before the producer waits for write completions
constexpr auto kTick = std::chrono::milliseconds(1);
constexpr auto kReconnectDelay = std::chrono::seconds(1);
constexpr const char* kNodeHeader = "S7-Node"; // the sender's node UUID, in both handshake directions

} // namespace

struct BeastRuntimeNetEndpoint::Impl : std::enable_shared_from_this<BeastRuntimeNetEndpoint::Impl> {
    struct Connection;
    using ConnectionPtr = std::shared_ptr<Connection>;
    struct Link;

    // A WebSocket connection (plain or TLS). Every member is used on the I/O
    // thread only.
    struct Connection : std::enable_shared_from_this<Connection> {
        Impl& impl;
        bool is_data{false};
        bool outbound{false};
        std::shared_ptr<Link> link; // outbound: the link it belongs to
        ControlPeer peer;
        stream::ConsumerKey consumer_key{"anonymous"};
        // The peer's node: from its verified certificate over TLS; over plain
        // WebSocket as it claims (S7-Node header) or as configured (data peer).
        std::string peer_node;
        std::string claimed_node; // S7-Node header received in the handshake
        // Consumer side: aliases of the local consumer streams RESUMEd here;
        // packets for any other alias are refused.
        std::unordered_set<std::uint32_t> resumed;
        std::unique_ptr<PlainWs> plain;
        std::unique_ptr<TlsWs> tls;
        boost::beast::flat_buffer read_buffer;
        std::deque<std::pair<std::shared_ptr<const Bytes>, bool>> writes; // bytes, binary
        bool writing{false};
        bool closed{false};
        // Producer side: streams this peer consumes, alias (theirs) -> local handle.
        std::unordered_map<std::uint32_t, std::uint64_t> producing;
        std::unordered_map<std::uint64_t, std::uint32_t> producing_alias;
        // RESUMEs for streams not (yet) produced here.
        std::unordered_map<std::string, wire::ControlMessage> pending_resumes;
        // Outbound control: the response to the request in flight.
        std::shared_ptr<std::promise<std::string>> pending_response;

        explicit Connection(Impl& owner) : impl(owner) {}

        template <typename F>
        void with_ws(F&& f)
        {
            if (tls) {
                f(*tls);
            } else {
                f(*plain);
            }
        }

        // Announces this node in the handshake (request or response).
        void decorate()
        {
            if (impl.node_uuid.empty()) {
                return;
            }
            with_ws([uuid = impl.node_uuid](auto& ws) {
                ws.set_option(websocket::stream_base::decorator([uuid](auto& message) { message.set(kNodeHeader, uuid); }));
            });
        }

        void start()
        {
            with_ws([this](auto& ws) {
                ws.set_option(websocket::stream_base::timeout::suggested(boost::beast::role_type::server));
                ws.read_message_max(is_data ? wire::kMaxPayloadBytes + 4096 : kMaxControlMessageBytes);
            });
            read();
        }

        void read()
        {
            with_ws([self = shared_from_this()](auto& ws) {
                ws.async_read(self->read_buffer, [self](const boost::system::error_code& ec, std::size_t) {
                    self->on_read(ec);
                });
            });
        }

        void on_read(const boost::system::error_code& ec)
        {
            if (ec) {
                close();
                return;
            }
            const auto data = read_buffer.cdata();
            const std::span<const std::uint8_t> message(static_cast<const std::uint8_t*>(data.data()), data.size());
            ++impl.messages_received;
            if (is_data) {
                impl.on_data_message(*this, message);
            } else {
                impl.on_control_message(*this, std::string(reinterpret_cast<const char*>(message.data()), message.size()));
            }
            read_buffer.consume(read_buffer.size());
            if (!closed) {
                read();
            }
        }

        void send(std::shared_ptr<const Bytes> bytes, const bool binary)
        {
            if (closed) {
                return;
            }
            writes.emplace_back(std::move(bytes), binary);
            if (!writing) {
                write_next();
            }
        }

        void write_next()
        {
            if (writes.empty() || closed) {
                writing = false;
                return;
            }
            writing = true;
            auto [bytes, binary] = writes.front();
            with_ws([self = shared_from_this(), bytes, binary](auto& ws) {
                ws.binary(binary);
                ws.async_write(boost::asio::buffer(*bytes), [self, bytes](const boost::system::error_code& ec, std::size_t) {
                    if (ec) {
                        self->close();
                        return;
                    }
                    ++self->impl.messages_sent;
                    self->writes.pop_front();
                    self->write_next();
                    if (self->is_data && self->writes.size() < kMaxQueuedWrites / 2) {
                        self->impl.pump_connection(*self);
                    }
                });
            });
        }

        void close()
        {
            if (closed) {
                return;
            }
            closed = true;
            boost::system::error_code ignored;
            if (tls) {
                boost::beast::get_lowest_layer(*tls).socket().close(ignored);
            } else if (plain) {
                boost::beast::get_lowest_layer(*plain).socket().close(ignored);
            }
            if (pending_response) {
                pending_response->set_exception(std::make_exception_ptr(std::runtime_error("control connection closed")));
                pending_response.reset();
            }
            impl.on_connection_closed(shared_from_this());
        }
    };

    explicit Impl(TransportLimits limits, std::string state_dir)
        : limits(limits)
        , sequences(state_dir.empty() ? std::unique_ptr<stream::SequenceStore>(std::make_unique<stream::MemorySequenceStore>())
                                      : std::unique_ptr<stream::SequenceStore>(
                                            std::make_unique<stream::FileSequenceStore>(std::filesystem::path(state_dir) / "streams")))
        , table(*sequences)
    {
    }

    void start()
    {
        auto weak = weak_from_this();
        table.on_producer_data = [weak](StreamEntry&) {
            if (const auto self = weak.lock()) {
                self->schedule_pump();
            }
        };
        table.on_consumer_opened = [weak](StreamEntry& entry) {
            if (const auto self = weak.lock()) {
                const auto resume = entry.consumer->resume_message();
                boost::asio::post(self->io, [self, resume, producer_node = entry.config.producer_node] {
                    for (const auto& connection : self->connections) {
                        if (connection->is_data && !connection->closed && may_produce(*connection, producer_node)) {
                            connection->resumed.insert(resume.stream_alias);
                            connection->send(std::make_shared<const Bytes>(to_bytes(resume)), true);
                        }
                    }
                });
            }
        };
        io_thread = std::thread([self = shared_from_this()] { self->io.run(); });
        schedule_tick();
    }

    void stop()
    {
        boost::asio::post(io, [self = shared_from_this()] {
            self->stopping = true;
            boost::system::error_code ignored;
            for (const auto& listener : self->listeners) {
                if (listener) listener->acceptor.close(ignored);
            }
            self->tick_timer.cancel();
            for (const auto& connection : std::vector<ConnectionPtr>(self->connections.begin(), self->connections.end())) {
                connection->close();
            }
            self->work.reset();
        });
        if (io_thread.joinable()) {
            io_thread.join();
        }
        control_pool.join();
        table.changed.notify_all();
    }

    [[nodiscard]] static Bytes to_bytes(const wire::ControlMessage& message)
    {
        const auto bytes = wire::encode_control_message(message);
        return Bytes(bytes.begin(), bytes.end());
    }

    // Whether the connection's peer may produce a stream configured with
    // producer_node / consume a stream with this configuration.
    [[nodiscard]] static bool may_produce(const Connection& connection, const std::string& producer_node)
    {
        return producer_node.empty() || connection.peer_node == producer_node;
    }
    [[nodiscard]] static bool may_consume(const Connection& connection, const stream::StreamConfig& config)
    {
        return config.consumer_nodes.empty() || std::ranges::find(config.consumer_nodes, connection.peer_node) != config.consumer_nodes.end();
    }

    [[nodiscard]] static std::string describe_peer(const Connection& connection)
    {
        return connection.peer_node.empty() ? std::string("an unidentified peer") : "node " + connection.peer_node;
    }

    void record_error(std::string error)
    {
        std::lock_guard lock(errors_mutex);
        if (errors.size() == 32) {
            errors.pop_front();
        }
        errors.push_back(std::move(error));
    }

    // ---- data path (I/O thread) -------------------------------------------

    void on_data_message(Connection& connection, const std::span<const std::uint8_t> message)
    {
        try {
            if (wire::is_control_message(message)) {
                on_stream_control(connection, wire::decode_control_message(message));
            } else {
                on_data_packet(connection, wire::decode_data_packet(message));
            }
        } catch (const wire::FormatError& ex) {
            ++malformed_messages;
            record_error(std::string("malformed message from peer: ") + ex.what());
            connection.close(); // the peer reconnects and resumes
        }
    }

    void on_stream_control(Connection& connection, const wire::ControlMessage& message)
    {
        std::unique_lock lock(table.mutex);
        if (message.kind == wire::ControlKind::Ack) {
            const auto it = connection.producing.find(message.stream_alias);
            if (it != connection.producing.end()) {
                if (auto* entry = table.find(StreamHandle{it->second})) {
                    entry->producer->acknowledge(connection.consumer_key, message.next_expected);
                    table.changed.notify_all();
                }
            }
        } else {
            const auto next = message.kind == wire::ControlKind::ResumeNoState ? 0 : message.next_expected;
            auto* entry = table.find_producer(message.stream_id);
            if (!entry) {
                // Not produced here (yet): remember it in case the producer opens later.
                auto pending = message;
                pending.next_expected = next;
                connection.pending_resumes[stream_key(message.stream_id)] = pending;
                return;
            }
            if (!attach(connection, *entry, message.stream_alias, next)) {
                return;
            }
        }
        lock.unlock();
        pump_connection(connection);
    }

    // Lock held. A consumer receives a stream through one connection: when
    // its RESUME arrives on another connection (two connections between the
    // same nodes, or a reconnect before the old connection noticed it was
    // gone), the latest RESUME wins, so packets are never sent on two
    // connections at once and cannot overtake each other.
    // A peer that is not a configured consumer is refused (false).
    bool attach(Connection& connection, StreamEntry& entry, const std::uint32_t alias, const std::uint64_t next)
    {
        if (!may_consume(connection, entry.config)) {
            ++entry.unauthorized;
            entry.note(FaultCode::UnauthorizedConsumer, describe_peer(connection));
            record_error("refused RESUME of stream " + wire::to_string(entry.config.stream_id) + " from " + describe_peer(connection) +
                         ": not a configured consumer");
            return false;
        }
        auto& route = routes[{entry.handle.value, connection.consumer_key}];
        if (const auto previous = route.lock(); previous && previous.get() != &connection) {
            if (const auto it = previous->producing_alias.find(entry.handle.value); it != previous->producing_alias.end()) {
                previous->producing.erase(it->second);
                previous->producing_alias.erase(it);
            }
        }
        route = connection.weak_from_this();
        entry.producer->resume(connection.consumer_key, alias, next);
        connection.producing[alias] = entry.handle.value;
        connection.producing_alias[entry.handle.value] = alias;
        table.changed.notify_all();
        return true;
    }

    void on_data_packet(Connection& connection, const wire::DataPacket& packet)
    {
        std::unique_lock lock(table.mutex);
        auto* entry = table.find_consumer_by_alias(packet.stream_alias);
        if (!entry) {
            return; // a stream closed meanwhile
        }
        if (!connection.resumed.contains(packet.stream_alias)) {
            // Not RESUMEd here: this peer is not the stream's producer.
            ++entry->unauthorized;
            entry->note(FaultCode::UnauthorizedProducer, describe_peer(connection));
            const auto id = entry->config.stream_id;
            lock.unlock();
            record_error("refused packets of stream " + wire::to_string(id) + " from " + describe_peer(connection) +
                         ": not the configured producer");
            connection.close();
            return;
        }
        if (entry->consumer->on_packet(packet, Clock::now())) {
            entry->note_late();
        }
        consumer_sources[entry->handle.value] = connection.weak_from_this();
        table.changed.notify_all();
    }

    void schedule_pump()
    {
        boost::asio::post(io, [weak = weak_from_this()] {
            if (const auto self = weak.lock()) {
                for (const auto& connection : self->connections) {
                    if (connection->is_data && !connection->closed) {
                        self->apply_pending_resumes(*connection);
                        self->pump_connection(*connection);
                    }
                }
            }
        });
    }

    void apply_pending_resumes(Connection& connection)
    {
        if (connection.pending_resumes.empty()) {
            return;
        }
        std::lock_guard lock(table.mutex);
        for (auto it = connection.pending_resumes.begin(); it != connection.pending_resumes.end();) {
            if (auto* entry = table.find_producer(it->second.stream_id)) {
                static_cast<void>(attach(connection, *entry, it->second.stream_alias, it->second.next_expected));
                it = connection.pending_resumes.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Sends the producer streams' next packets to this connection, bounded by
    // the write queue (the rest follows on write completion).
    void pump_connection(Connection& connection)
    {
        if (connection.closed || !connection.is_data) {
            return;
        }
        std::lock_guard lock(table.mutex);
        bool progress = true;
        while (progress && connection.writes.size() < kMaxQueuedWrites) {
            progress = false;
            for (const auto& [handle, alias] : connection.producing_alias) {
                auto* entry = table.find(StreamHandle{handle});
                if (!entry) {
                    continue;
                }
                if (auto message = entry->producer->next_message(connection.consumer_key)) {
                    connection.send(std::make_shared<const Bytes>(std::move(*message)), true);
                    progress = true;
                }
            }
        }
    }

    void schedule_tick()
    {
        tick_timer.expires_after(kTick);
        tick_timer.async_wait([weak = weak_from_this()](const boost::system::error_code& ec) {
            const auto self = weak.lock();
            if (ec || !self || self->stopping) {
                return;
            }
            self->on_tick();
            self->schedule_tick();
        });
    }

    // Flushes due batches and sends due acknowledgements.
    void on_tick()
    {
        const auto now = Clock::now();
        bool flushed = false;
        std::vector<std::pair<std::shared_ptr<Connection>, Bytes>> acks;
        {
            std::lock_guard lock(table.mutex);
            table.for_each([&](StreamEntry& entry) {
                if (entry.producer) {
                    flushed |= entry.producer->flush(now);
                } else if (const auto ack = entry.consumer->ack_due(now)) {
                    if (const auto it = consumer_sources.find(entry.handle.value); it != consumer_sources.end()) {
                        if (auto connection = it->second.lock()) {
                            acks.emplace_back(std::move(connection), to_bytes(*ack));
                        }
                    }
                }
            });
            if (flushed) {
                table.changed.notify_all();
            }
        }
        for (auto& [connection, bytes] : acks) {
            connection->send(std::make_shared<const Bytes>(std::move(bytes)), true);
        }
        if (flushed) {
            for (const auto& connection : connections) {
                pump_connection(*connection);
            }
        }
    }

    // A new data connection: resume every local consumer stream on it.
    void on_data_connection(Connection& connection)
    {
        std::vector<Bytes> resumes;
        {
            std::lock_guard lock(table.mutex);
            table.for_each([&](StreamEntry& entry) {
                if (entry.consumer && may_produce(connection, entry.config.producer_node)) {
                    const auto resume = entry.consumer->resume_message();
                    connection.resumed.insert(resume.stream_alias);
                    resumes.push_back(to_bytes(resume));
                }
            });
        }
        for (auto& bytes : resumes) {
            connection.send(std::make_shared<const Bytes>(std::move(bytes)), true);
        }
    }

    void on_connection_closed(const ConnectionPtr& connection)
    {
        {
            std::lock_guard lock(table.mutex);
            for (const auto& [handle, _] : connection->producing_alias) {
                const auto route = routes.find({handle, connection->consumer_key});
                if (route != routes.end() && route->second.lock() == connection) {
                    routes.erase(route);
                    if (auto* entry = table.find(StreamHandle{handle})) {
                        entry->producer->detach(connection->consumer_key);
                    }
                }
            }
        }
        connections.erase(connection);
        // A dropped connection of the current client configuration reconnects;
        // connections replaced by configure_client() do not.
        if (connection->outbound && connection->link && current(connection->link)) {
            schedule_reconnect(connection->link);
        }
    }

    // ---- control path -------------------------------------------------------

    void on_control_message(Connection& connection, std::string text)
    {
        if (connection.outbound) {
            if (auto pending = std::exchange(connection.pending_response, nullptr)) {
                pending->set_value(std::move(text));
            }
            return;
        }
        ControlRequestHandler handler;
        {
            std::lock_guard lock(handler_mutex);
            handler = control_handler;
        }
        boost::asio::post(control_pool, [self = shared_from_this(), connection = connection.shared_from_this(), handler,
                                         text = std::move(text)] {
            std::string response;
            try {
                response = handler ? handler(connection->peer, text)
                                   : R"({"type":"ERROR","protocol_version":1,"code":"INTERNAL_ERROR","message":"No control handler registered"})";
            } catch (...) {
                response = R"({"type":"ERROR","protocol_version":1,"code":"INTERNAL_ERROR","message":"Control handler failed"})";
            }
            boost::asio::post(self->io, [connection, response = std::move(response)] {
                const auto* begin = reinterpret_cast<const std::uint8_t*>(response.data());
                connection->send(std::make_shared<const Bytes>(begin, begin + response.size()), false);
            });
        });
    }

    // ---- server -------------------------------------------------------------

    struct Listener {
        Tcp::acceptor acceptor;
        std::shared_ptr<ssl::context> tls;
        ListenerChannels channels;

        Listener(boost::asio::io_context& io, std::shared_ptr<ssl::context> context, ListenerChannels allowed)
            : acceptor(io), tls(std::move(context)), channels(allowed) {}
    };

    void accept(const std::shared_ptr<Listener>& listener)
    {
        listener->acceptor.async_accept([self = shared_from_this(), listener](const boost::system::error_code& ec, Tcp::socket socket) {
            if (self->stopping || ec == boost::asio::error::operation_aborted) {
                return;
            }
            if (ec) {
                self->record_error("accept failed: " + ec.message());
                self->accept(listener);
                return;
            }
            std::size_t inbound = 0;
            for (const auto& connection : self->connections) {
                inbound += connection->outbound ? 0 : 1;
            }
            if (inbound >= self->limits.max_inbound_connections) {
                ++self->connections_rejected;
                boost::system::error_code ignored;
                socket.close(ignored);
            } else {
                self->handshake_inbound(std::move(socket), listener);
            }
            self->accept(listener);
        });
    }

    void handshake_inbound(Tcp::socket socket, const std::shared_ptr<Listener>& listener)
    {
        auto connection = std::make_shared<Connection>(*this);
        auto request = std::make_shared<http::request<http::string_body>>();
        auto buffer = std::make_shared<boost::beast::flat_buffer>();
        auto finish = [self = shared_from_this(), connection, request, listener](const boost::system::error_code& ec) {
            if (ec || self->stopping) {
                return;
            }
            const auto target = std::string(request->target());
            const bool data = target.ends_with("/data");
            const bool control = target.ends_with("/control");
            if ((!data && !control) || (data && listener->channels == ListenerChannels::Control) ||
                (control && listener->channels == ListenerChannels::Data)) {
                ++self->connections_rejected;
                // This connection is not registered. Close the socket now;
                // an asynchronous close here could outlive its owner or wait
                // indefinitely for a peer to finish the close handshake.
                connection->close();
                return;
            }
            connection->is_data = target.ends_with("/data");
            connection->claimed_node = std::string((*request)[kNodeHeader]);
            self->register_connection(connection);
        };
        if (listener->tls) {
            connection->tls = std::make_unique<TlsWs>(boost::beast::tcp_stream(std::move(socket)), *listener->tls);
            boost::beast::get_lowest_layer(*connection->tls).expires_after(std::chrono::seconds(10));
            connection->tls->next_layer().async_handshake(
                ssl::stream_base::server, [self = shared_from_this(), connection, request, buffer, finish](const boost::system::error_code& ec) {
                    if (ec) {
                        return;
                    }
                    connection->peer = ControlPeer{true, verified_peer_certificate(connection->tls->next_layer().native_handle())};
                    http::async_read(connection->tls->next_layer(), *buffer, *request,
                                     [connection, request, buffer, finish](const boost::system::error_code& read_ec, std::size_t) {
                                         if (read_ec) {
                                             return;
                                         }
                                         boost::beast::get_lowest_layer(*connection->tls).expires_never();
                                         connection->decorate();
                                         connection->tls->async_accept(*request, finish);
                                     });
                });
        } else {
            connection->plain = std::make_unique<PlainWs>(boost::beast::tcp_stream(std::move(socket)));
            boost::beast::get_lowest_layer(*connection->plain).expires_after(std::chrono::seconds(10));
            http::async_read(connection->plain->next_layer(), *buffer, *request,
                             [connection, request, buffer, finish](const boost::system::error_code& ec, std::size_t) {
                                 if (ec) {
                                     return;
                                 }
                                 boost::beast::get_lowest_layer(*connection->plain).expires_never();
                                 connection->decorate();
                                 connection->plain->async_accept(*request, finish);
                             });
        }
    }

    void register_connection(const ConnectionPtr& connection)
    {
        if (connection->tls) {
            const auto& certificate = connection->peer.certificate;
            connection->peer_node = certificate ? node_uuid_of(*certificate).value_or("") : "";
        } else {
            connection->peer_node = !connection->claimed_node.empty() ? connection->claimed_node
                                    : connection->link                ? connection->link->expected_node_uuid
                                                                      : std::string{};
        }
        if (connection->peer.certificate) {
            connection->consumer_key = connection->peer.certificate->fingerprint_sha256;
        } else if (!connection->peer_node.empty()) {
            connection->consumer_key = "node:" + connection->peer_node;
        }
        connections.insert(connection);
        connection->start();
        if (connection->is_data) {
            on_data_connection(*connection);
        }
    }

    // ---- client -------------------------------------------------------------

    // An outbound peer kept connected: the control client (/control and
    // /data) or a data peer (/data only). Replacing or removing a link bumps
    // nothing in place: the old Link object is dropped, so its connections
    // and pending reconnects see they are no longer current.
    struct Link {
        std::string key; // kClientLink or "data:" + url
        ParsedWebSocketUrl url;
        std::shared_ptr<ssl::context> tls;
        bool control{false};
        bool data{true};
        bool reconnect_scheduled{false};
        std::string expected_node_uuid; // data peers over TLS: the producer's identity
    };
    using LinkPtr = std::shared_ptr<Link>;
    static constexpr const char* kClientLink = "client";

    [[nodiscard]] bool current(const LinkPtr& link) const
    {
        const auto it = links.find(link->key);
        return !stopping && it != links.end() && it->second == link;
    }

    void add_link(const LinkPtr& link, std::function<void(std::exception_ptr)> done)
    {
        remove_link(link->key);
        links[link->key] = link;
        connect_link(link, std::move(done));
    }

    void remove_link(const std::string& key)
    {
        const auto it = links.find(key);
        if (it == links.end()) {
            return;
        }
        const auto link = it->second;
        links.erase(it);
        for (const auto& connection : std::vector<ConnectionPtr>(connections.begin(), connections.end())) {
            if (connection->link == link) {
                connection->close();
            }
        }
    }

    // Connects the link's channels; reports through `done` once all finished.
    void connect_link(const LinkPtr& link, std::function<void(std::exception_ptr)> done)
    {
        std::vector<bool> channels;
        if (link->control) channels.push_back(false);
        if (link->data) channels.push_back(true);
        auto pending = std::make_shared<std::size_t>(channels.size());
        auto failure = std::make_shared<std::exception_ptr>();
        auto complete = [done, pending, failure](std::exception_ptr error) {
            if (error && !*failure) {
                *failure = error;
            }
            if (--*pending == 0 && done) {
                done(*failure);
            }
        };
        for (const bool is_data : channels) {
            connect_one(link, is_data, complete);
        }
    }

    void connect_one(const LinkPtr& link, const bool is_data, std::function<void(std::exception_ptr)> complete)
    {
        const auto& url = link->url;
        auto connection = std::make_shared<Connection>(*this);
        connection->outbound = true;
        connection->is_data = is_data;
        connection->link = link;
        const auto target = ws_target_for_path(url, is_data ? "/data" : "/control");
        const auto host = (url.host.find(':') != std::string::npos ? "[" + url.host + "]" : url.host) + ":" + url.port;
        auto fail = [complete](const boost::system::error_code& ec, const char* stage) {
            complete(std::make_exception_ptr(std::runtime_error(std::string("connect failed (") + stage + "): " + ec.message())));
        };
        auto response = std::make_shared<websocket::response_type>();
        auto resolver = std::make_shared<Tcp::resolver>(io);
        resolver->async_resolve(url.host, url.port, [self = shared_from_this(), resolver, connection, link, target, host, complete, fail,
                                                     response](const boost::system::error_code& ec, Tcp::resolver::results_type results) {
            if (ec) {
                return fail(ec, "resolve");
            }
            auto on_ws = [self, connection, link, complete, fail, response](const boost::system::error_code& ws_ec) {
                if (ws_ec) {
                    return fail(ws_ec, "websocket handshake");
                }
                if (!self->current(link)) {
                    connection->close();
                    return complete(nullptr);
                }
                connection->claimed_node = std::string((*response)[kNodeHeader]);
                if (!connection->tls && !link->expected_node_uuid.empty() && !connection->claimed_node.empty() &&
                    connection->claimed_node != link->expected_node_uuid) {
                    const auto error = "data peer " + link->url.host + ":" + link->url.port + " is node " + connection->claimed_node +
                                       ", not node " + link->expected_node_uuid + " (identity mismatch)";
                    self->record_error(error);
                    connection->close();
                    return complete(std::make_exception_ptr(std::runtime_error(error)));
                }
                if (connection->tls) {
                    connection->peer = ControlPeer{true, verified_peer_certificate(connection->tls->next_layer().native_handle())};
                    if (!link->expected_node_uuid.empty() &&
                        check_node_identity(connection->peer.certificate, link->expected_node_uuid) != NodeIdentity::Verified) {
                        const auto error = "data peer " + link->url.host + ":" + link->url.port + " is not node " +
                                           link->expected_node_uuid + " (certificate identity mismatch)";
                        self->record_error(error);
                        connection->close();
                        return complete(std::make_exception_ptr(std::runtime_error(error)));
                    }
                }
                self->register_connection(connection);
                complete(nullptr);
            };
            if (link->tls) {
                connection->tls = std::make_unique<TlsWs>(boost::beast::tcp_stream(self->io), *link->tls);
                auto& tcp = boost::beast::get_lowest_layer(*connection->tls);
                tcp.expires_after(std::chrono::seconds(10));
                tcp.async_connect(results, [connection, target, host, on_ws, fail, response](const boost::system::error_code& c_ec, const auto&) {
                    if (c_ec) {
                        return fail(c_ec, "tcp connect");
                    }
                    connection->tls->next_layer().async_handshake(ssl::stream_base::client, [connection, target, host, on_ws, fail, response](const boost::system::error_code& h_ec) {
                        if (h_ec) {
                            return fail(h_ec, "tls handshake");
                        }
                        boost::beast::get_lowest_layer(*connection->tls).expires_never();
                        connection->decorate();
                        connection->tls->async_handshake(*response, host, target, on_ws);
                    });
                });
            } else {
                connection->plain = std::make_unique<PlainWs>(boost::beast::tcp_stream(self->io));
                auto& tcp = boost::beast::get_lowest_layer(*connection->plain);
                tcp.expires_after(std::chrono::seconds(10));
                tcp.async_connect(results, [connection, target, host, on_ws, fail, response](const boost::system::error_code& c_ec, const auto&) {
                    if (c_ec) {
                        return fail(c_ec, "tcp connect");
                    }
                    boost::beast::get_lowest_layer(*connection->plain).expires_never();
                    connection->decorate();
                    connection->plain->async_handshake(*response, host, target, on_ws);
                });
            }
        });
    }

    void schedule_reconnect(const LinkPtr& link)
    {
        if (link->reconnect_scheduled || !current(link)) {
            return;
        }
        link->reconnect_scheduled = true;
        auto timer = std::make_shared<boost::asio::steady_timer>(io, kReconnectDelay);
        timer->async_wait([self = shared_from_this(), timer, link](const boost::system::error_code& ec) {
            link->reconnect_scheduled = false;
            if (ec || !self->current(link)) {
                return;
            }
            // Drop the surviving channel (if any) and reconnect all of them.
            for (const auto& connection : std::vector<ConnectionPtr>(self->connections.begin(), self->connections.end())) {
                if (connection->link == link) {
                    connection->close();
                }
            }
            self->connect_link(link, [self, link](const std::exception_ptr& error) {
                if (error) {
                    self->schedule_reconnect(link);
                }
            });
        });
    }

    template <typename F>
    auto run_on_io(F&& f) -> decltype(f())
    {
        using R = decltype(f());
        std::packaged_task<R()> task(std::forward<F>(f));
        auto future = task.get_future();
        boost::asio::post(io, [&task] { task(); });
        return future.get();
    }

    TransportLimits limits;
    boost::asio::io_context io;
    std::optional<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> work{io.get_executor()};
    boost::asio::thread_pool control_pool{1};
    std::thread io_thread;
    boost::asio::steady_timer tick_timer{io};
    std::unique_ptr<stream::SequenceStore> sequences;
    StreamTable table;

    // I/O thread only:
    std::string node_uuid; // this node, announced in handshakes
    bool stopping{false};
    std::array<std::shared_ptr<Listener>, 2> listeners;
    std::unordered_map<std::string, LinkPtr> links;
    std::unordered_set<ConnectionPtr> connections;
    std::unordered_map<std::uint64_t, std::weak_ptr<Connection>> consumer_sources; // consumer handle -> data source (lock: table.mutex)
    // (producer handle, consumer key) -> the connection the consumer receives on (lock: table.mutex).
    std::map<std::pair<std::uint64_t, stream::ConsumerKey>, std::weak_ptr<Connection>> routes;

    std::mutex handler_mutex;
    ControlRequestHandler control_handler;
    std::mutex request_mutex; // one outbound control request at a time
    std::mutex errors_mutex;
    std::deque<std::string> errors;
    std::atomic<std::uint64_t> connections_rejected{0};
    std::atomic<std::uint64_t> messages_sent{0};
    std::atomic<std::uint64_t> messages_received{0};
    std::atomic<std::uint64_t> malformed_messages{0};
};

BeastRuntimeNetEndpoint::BeastRuntimeNetEndpoint(TransportLimits limits, std::string state_dir)
    : impl_(std::make_shared<Impl>(limits, std::move(state_dir)))
{
    impl_->start();
}

BeastRuntimeNetEndpoint::~BeastRuntimeNetEndpoint()
{
    impl_->stop();
}

auto BeastRuntimeNetEndpoint::backend_name() const -> std::string
{
    return "beast";
}

void BeastRuntimeNetEndpoint::set_node_uuid(const std::string& node_uuid)
{
    impl_->run_on_io([&] { impl_->node_uuid = node_uuid; });
}

auto BeastRuntimeNetEndpoint::configure_server(const std::uint16_t port, const TlsConfig& tls, const std::string& bind_address,
                                               const ListenerChannels channels)
    -> std::uint16_t
{
    std::shared_ptr<ssl::context> context;
    if (tls.enabled) {
        if (tls.cert_file.empty() || tls.key_file.empty() || tls.ca_file.empty()) {
            throw std::invalid_argument("TLS server requires cert_file, key_file, and ca_file.");
        }
        context = std::make_shared<ssl::context>(ssl::context::tls_server);
        context->set_options(ssl::context::default_workarounds | ssl::context::no_sslv2 | ssl::context::single_dh_use);
        context->use_certificate_chain_file(tls.cert_file);
        context->use_private_key_file(tls.key_file, ssl::context::pem);
        context->load_verify_file(tls.ca_file);
        context->set_verify_mode(tls.require_client_cert ? (ssl::verify_peer | ssl::verify_fail_if_no_peer_cert) : ssl::verify_peer);
        // With peer verification OpenSSL resumes a session only within a session id context;
        // without one it refuses every resumed handshake with a fatal internal_error alert
        // (JSSE clients resume on every reconnect). One context per kind of listener: a
        // session keeps the verified client certificate, so it resumes only on a listener
        // with the same policy.
        const std::string_view session_context = channels == ListenerChannels::Data      ? "s7transport/data"
                                                 : channels == ListenerChannels::Control ? "s7transport/control"
                                                                                         : "s7transport/shared";
        SSL_CTX_set_session_id_context(context->native_handle(), reinterpret_cast<const unsigned char*>(session_context.data()),
                                       static_cast<unsigned int>(session_context.size()));
    }
    return impl_->run_on_io([&]() -> std::uint16_t {
        auto& slot = impl_->listeners[channels == ListenerChannels::Data ? 1 : 0];
        if (slot) {
            const auto listening = slot->acceptor.local_endpoint().port();
            if ((port == 0 || listening == port) && slot->channels == channels) {
                return listening;
            }
            throw std::logic_error("BeastRuntimeNetEndpoint server is already listening on another port.");
        }
        auto listener = std::make_shared<Impl::Listener>(impl_->io, context, channels);
        auto& acceptor = listener->acceptor;
        const auto address = boost::asio::ip::make_address(
            !bind_address.empty() ? bind_address : (context ? std::string("0.0.0.0") : std::string("127.0.0.1")));
        const Tcp::endpoint endpoint(address, port);
        acceptor.open(endpoint.protocol());
        acceptor.set_option(Tcp::acceptor::reuse_address(true));
        acceptor.bind(endpoint);
        acceptor.listen();
        slot = listener;
        impl_->accept(listener);
        return acceptor.local_endpoint().port();
    });
}

auto BeastRuntimeNetEndpoint::configure_data_server(const std::uint16_t port, const TlsConfig& tls,
                                                    const std::string& bind_address) -> std::uint16_t
{
    return configure_server(port, tls, bind_address, ListenerChannels::Data);
}

namespace {

auto make_client_tls(const ParsedWebSocketUrl& url, const TlsConfig& tls) -> std::shared_ptr<ssl::context>
{
    if (!url.secure && !tls.enabled) {
        return nullptr;
    }
    if (tls.cert_file.empty() || tls.key_file.empty() || tls.ca_file.empty()) {
        throw std::invalid_argument("TLS client requires cert_file, key_file, and ca_file.");
    }
    auto context = std::make_shared<ssl::context>(ssl::context::tls_client);
    context->set_default_verify_paths();
    context->use_certificate_chain_file(tls.cert_file);
    context->use_private_key_file(tls.key_file, ssl::context::pem);
    context->load_verify_file(tls.ca_file);
    context->set_verify_mode(ssl::verify_peer);
    return context;
}

} // namespace

void BeastRuntimeNetEndpoint::configure_client(const std::string& url, const TlsConfig& tls, const bool connect_data)
{
    auto link = std::make_shared<Impl::Link>();
    link->key = Impl::kClientLink;
    link->url = parse_ws_url(url);
    link->tls = make_client_tls(link->url, tls);
    link->control = true;
    link->data = connect_data;
    auto result = std::make_shared<std::promise<void>>();
    auto future = result->get_future();
    boost::asio::post(impl_->io, [impl = impl_, link, result] {
        impl->add_link(link, [impl, link, result](const std::exception_ptr& error) {
            if (error) {
                impl->remove_link(link->key);
                result->set_exception(error);
            } else {
                result->set_value();
            }
        });
    });
    future.get();
}

void BeastRuntimeNetEndpoint::set_data_peers(const std::vector<DataPeer>& peers, const TlsConfig& tls)
{
    std::vector<std::shared_ptr<Impl::Link>> wanted;
    for (const auto& peer : peers) {
        auto link = std::make_shared<Impl::Link>();
        link->key = "data:" + peer.url + "#" + peer.node_uuid;
        link->url = parse_ws_url(peer.url);
        if (peer.trusted_plaintext && link->url.secure) {
            throw std::invalid_argument("trusted_plaintext data requires a ws:// endpoint.");
        }
        if (!peer.trusted_plaintext && tls.enabled && !link->url.secure) {
            throw std::invalid_argument("Plaintext data with TLS node credentials requires explicit trusted_plaintext permission.");
        }
        link->tls = make_client_tls(link->url, peer.trusted_plaintext ? TlsConfig{} : tls);
        link->expected_node_uuid = peer.node_uuid;
        wanted.push_back(std::move(link));
    }
    impl_->run_on_io([&] {
        std::vector<std::string> obsolete;
        for (const auto& [key, _] : impl_->links) {
            const bool keep = std::ranges::any_of(wanted, [&](const auto& link) { return link->key == key; });
            if (key != Impl::kClientLink && !keep) {
                obsolete.push_back(key);
            }
        }
        for (const auto& key : obsolete) {
            impl_->remove_link(key);
        }
        for (const auto& link : wanted) {
            if (impl_->links.contains(link->key)) {
                continue; // already connected (or reconnecting)
            }
            impl_->links[link->key] = link;
            impl_->connect_link(link, [impl = impl_, link](const std::exception_ptr& error) {
                if (error) {
                    impl->schedule_reconnect(link);
                }
            });
        }
    });
}

auto BeastRuntimeNetEndpoint::server_certificate() const -> std::optional<PeerCertificate>
{
    return impl_->run_on_io([&]() -> std::optional<PeerCertificate> {
        for (const auto& connection : impl_->connections) {
            if (connection->link && connection->link->key == Impl::kClientLink && !connection->is_data && !connection->closed) {
                return connection->peer.certificate;
            }
        }
        return std::nullopt;
    });
}

void BeastRuntimeNetEndpoint::set_control_request_handler(ControlRequestHandler handler)
{
    std::lock_guard lock(impl_->handler_mutex);
    impl_->control_handler = std::move(handler);
}

auto BeastRuntimeNetEndpoint::request_control_json(const std::string& request_json) -> std::string
{
    std::lock_guard serialize(impl_->request_mutex);
    auto response = std::make_shared<std::promise<std::string>>();
    auto future = response->get_future();
    boost::asio::post(impl_->io, [impl = impl_, response, request_json] {
        for (const auto& connection : impl->connections) {
            if (connection->link && connection->link->key == Impl::kClientLink && !connection->is_data && !connection->closed) {
                connection->pending_response = response;
                const auto* begin = reinterpret_cast<const std::uint8_t*>(request_json.data());
                connection->send(std::make_shared<const Bytes>(begin, begin + request_json.size()), false);
                return;
            }
        }
        response->set_exception(std::make_exception_ptr(std::runtime_error("control channel is not connected")));
    });
    if (future.wait_for(std::chrono::seconds(10)) != std::future_status::ready) {
        throw std::runtime_error("control request timed out");
    }
    return future.get();
}

auto BeastRuntimeNetEndpoint::open_producer(const stream::StreamConfig& config) -> StreamHandle
{
    return impl_->table.open(config, StreamRole::Producer);
}

auto BeastRuntimeNetEndpoint::open_consumer(const stream::StreamConfig& config) -> StreamHandle
{
    return impl_->table.open(config, StreamRole::Consumer);
}

void BeastRuntimeNetEndpoint::close_stream(const StreamHandle handle)
{
    impl_->table.close(handle);
}

auto BeastRuntimeNetEndpoint::publish(const StreamHandle handle, const void* elements, const std::size_t count,
                                   const std::span<const wire::TimestampRecord> times) -> PublishResult
{
    return impl_->table.publish(handle, elements, count, times);
}

auto BeastRuntimeNetEndpoint::receive(const StreamHandle handle, void* elements, const std::size_t count) -> ReceiveResult
{
    return impl_->table.receive(handle, elements, count);
}

auto BeastRuntimeNetEndpoint::stream_statuses() const -> std::vector<StreamStatus>
{
    return impl_->table.statuses();
}

void BeastRuntimeNetEndpoint::set_clock_usable(const bool usable)
{
    impl_->table.set_clock_usable(usable);
}

void BeastRuntimeNetEndpoint::note_on_all_streams(const stream::FaultCode code, const std::string& detail)
{
    impl_->table.note_all(code, detail);
}

auto BeastRuntimeNetEndpoint::recover_stream(const wire::StreamId& stream_id) -> bool
{
    const bool found = impl_->table.recover(stream_id);
    std::lock_guard lock(impl_->table.mutex);
    impl_->table.for_each([&](StreamEntry& entry) {
        if (entry.producer && entry.config.stream_id == stream_id) {
            impl_->table.on_producer_data(entry);
        }
    });
    return found;
}

auto BeastRuntimeNetEndpoint::take_transport_errors() -> std::vector<std::string>
{
    std::lock_guard lock(impl_->errors_mutex);
    std::vector<std::string> result(std::make_move_iterator(impl_->errors.begin()), std::make_move_iterator(impl_->errors.end()));
    impl_->errors.clear();
    return result;
}

auto BeastRuntimeNetEndpoint::stats() const -> TransportStats
{
    TransportStats stats;
    impl_->run_on_io([&] {
        for (const auto& connection : impl_->connections) {
            if (connection->is_data) {
                ++stats.data_connections;
            } else {
                ++stats.control_connections;
            }
        }
    });
    stats.connections_rejected = impl_->connections_rejected.load();
    stats.messages_sent = impl_->messages_sent.load();
    stats.messages_received = impl_->messages_received.load();
    stats.malformed_messages = impl_->malformed_messages.load();
    return stats;
}

} // namespace s7::transport
