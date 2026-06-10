#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#include <pcap.h>

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

namespace {

constexpr int kEthernetHeaderLength = 14;
constexpr uint8_t kTcpFin = 0x01;
constexpr uint8_t kTcpSyn = 0x02;
constexpr uint8_t kTcpRst = 0x04;
constexpr uint8_t kTcpAck = 0x10;
volatile std::sig_atomic_t stop_capture = 0;

#pragma pack(push, 1)
struct Ipv4Header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};

struct TcpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence;
    uint32_t acknowledgement;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

struct UdpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};
#pragma pack(pop)

struct FlowKey {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::string protocol;

    bool operator<(const FlowKey& other) const {
        return std::tie(src_ip, dst_ip, src_port, dst_port, protocol) <
               std::tie(other.src_ip, other.dst_ip, other.src_port, other.dst_port, other.protocol);
    }
};

struct FlowStats {
    uint64_t source_bytes = 0;
    uint64_t destination_bytes = 0;
    uint32_t packet_count = 0;
    double first_seen = 0;
    double last_seen = 0;
    std::string flag = "SF";
};

struct PacketRow {
    double timestamp = 0;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::string protocol;
    std::string service;
    uint32_t length = 0;
    std::string flag = "SF";
};

struct CaptureState {
    std::map<FlowKey, FlowStats> flows;
    std::map<std::string, uint32_t> host_counts;
    std::vector<PacketRow> packets;
    uint32_t error_count = 0;
    uint32_t packet_count = 0;
};

double timestamp_seconds(const timeval& value) {
    return static_cast<double>(value.tv_sec) + static_cast<double>(value.tv_usec) / 1000000.0;
}

std::string json_escape(const std::string& value) {
    std::ostringstream escaped;
    for (char ch : value) {
        switch (ch) {
            case '"':
                escaped << "\\\"";
                break;
            case '\\':
                escaped << "\\\\";
                break;
            case '\n':
                escaped << "\\n";
                break;
            case '\r':
                escaped << "\\r";
                break;
            case '\t':
                escaped << "\\t";
                break;
            default:
                escaped << ch;
        }
    }
    return escaped.str();
}

std::string service_name(uint16_t port) {
    switch (port) {
        case 20:
        case 21:
            return "ftp";
        case 22:
            return "ssh";
        case 25:
        case 110:
        case 143:
        case 465:
        case 587:
        case 993:
        case 995:
            return "smtp";
        case 53:
            return "dns";
        case 80:
            return "http";
        case 443:
            return "https";
        default:
            return "http";
    }
}

std::string tcp_flag(uint8_t flags) {
    if ((flags & kTcpSyn) && !(flags & kTcpAck)) {
        return "S0";
    }
    if (flags & kTcpRst) {
        return "RSTO";
    }
    if (flags & kTcpFin) {
        return "SF";
    }
    if (flags & kTcpAck) {
        return "SF";
    }
    return "REJ";
}

bool is_noise_ipv4(const std::string& address) {
    in_addr parsed {};
    if (inet_pton(AF_INET, address.c_str(), &parsed) != 1) {
        return true;
    }
    const uint32_t value = ntohl(parsed.s_addr);
    const uint8_t first = static_cast<uint8_t>((value >> 24) & 0xff);
    const uint8_t second = static_cast<uint8_t>((value >> 16) & 0xff);
    if (value == 0xffffffffu) {
        return true;
    }
    return first == 0 || first == 127 || first >= 224 || (first == 169 && second == 254);
}

void signal_handler(int) {
    stop_capture = 1;
}

void packet_handler(u_char* user, const pcap_pkthdr* header, const u_char* packet) {
    auto* state = reinterpret_cast<CaptureState*>(user);
    if (!header || !packet || header->caplen < kEthernetHeaderLength + sizeof(Ipv4Header)) {
        return;
    }

    const auto* ip_header = reinterpret_cast<const Ipv4Header*>(packet + kEthernetHeaderLength);
    const uint8_t version = ip_header->version_ihl >> 4;
    const int ip_header_length = (ip_header->version_ihl & 0x0f) * 4;
    if (version != 4 || ip_header_length < 20 ||
        header->caplen < static_cast<bpf_u_int32>(kEthernetHeaderLength + ip_header_length)) {
        return;
    }

    char source_buffer[INET_ADDRSTRLEN] = {};
    char destination_buffer[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &ip_header->src_addr, source_buffer, sizeof(source_buffer));
    inet_ntop(AF_INET, &ip_header->dst_addr, destination_buffer, sizeof(destination_buffer));

    FlowKey key;
    key.src_ip = source_buffer;
    key.dst_ip = destination_buffer;
    if (is_noise_ipv4(key.src_ip) || is_noise_ipv4(key.dst_ip)) {
        return;
    }
    key.protocol = ip_header->protocol == IPPROTO_TCP ? "tcp" : ip_header->protocol == IPPROTO_UDP ? "udp" : "";
    if (key.protocol.empty()) {
        return;
    }

    const u_char* transport = packet + kEthernetHeaderLength + ip_header_length;
    const int remaining = header->caplen - kEthernetHeaderLength - ip_header_length;
    std::string flag = "SF";

    if (ip_header->protocol == IPPROTO_TCP) {
        if (remaining < static_cast<int>(sizeof(TcpHeader))) {
            return;
        }
        const auto* tcp = reinterpret_cast<const TcpHeader*>(transport);
        key.src_port = ntohs(tcp->src_port);
        key.dst_port = ntohs(tcp->dst_port);
        flag = tcp_flag(tcp->flags);
    } else if (ip_header->protocol == IPPROTO_UDP) {
        if (remaining < static_cast<int>(sizeof(UdpHeader))) {
            return;
        }
        const auto* udp = reinterpret_cast<const UdpHeader*>(transport);
        key.src_port = ntohs(udp->src_port);
        key.dst_port = ntohs(udp->dst_port);
    }

    const double seen_at = timestamp_seconds(header->ts);
    if (state->packets.size() < 500) {
        state->packets.push_back(PacketRow{
            seen_at,
            key.src_ip,
            key.dst_ip,
            key.src_port,
            key.dst_port,
            key.protocol,
            service_name(key.dst_port),
            header->len,
            flag,
        });
    }

    auto& flow = state->flows[key];
    if (flow.packet_count == 0) {
        flow.first_seen = seen_at;
        state->host_counts[key.dst_ip]++;
    }
    flow.last_seen = seen_at;
    flow.packet_count++;
    flow.source_bytes += header->len;
    flow.destination_bytes += std::max<uint32_t>(64, header->len / 3);
    flow.flag = flag;
    state->packet_count++;
    if (flag != "SF") {
        state->error_count++;
    }
}

std::string choose_device() {
    char error_buffer[PCAP_ERRBUF_SIZE] = {};
    pcap_if_t* devices = nullptr;
    if (pcap_findalldevs(&devices, error_buffer) != 0 || devices == nullptr) {
        return "";
    }

    std::string selected;
    std::string fallback;
    for (pcap_if_t* device = devices; device != nullptr; device = device->next) {
        if (!device->name || (device->flags & PCAP_IF_LOOPBACK)) {
            continue;
        }
        const std::string name = device->name;
        if (name.rfind("utun", 0) == 0 || name.rfind("awdl", 0) == 0 ||
            name.rfind("llw", 0) == 0 || name.rfind("bridge", 0) == 0) {
            continue;
        }
        if (fallback.empty()) {
            fallback = name;
        }
        if (name.rfind("en", 0) == 0 || name.rfind("eth", 0) == 0) {
            selected = name;
            break;
        }
    }
    if (selected.empty()) {
        selected = fallback;
    }
    if (selected.empty() && devices->name) {
        selected = devices->name;
    }
    pcap_freealldevs(devices);
    return selected;
}

void print_json(const CaptureState& state, const std::string& device, double duration) {
    std::cout << "{\"source\":\"pcap\",\"device\":\"" << json_escape(device) << "\",\"flows\":[";
    bool first = true;
    const double connection_rate = duration > 0 ? static_cast<double>(state.flows.size()) / duration : 0;
    const double error_rate = state.packet_count > 0
                                  ? static_cast<double>(state.error_count) / static_cast<double>(state.packet_count)
                                  : 0;

    for (const auto& item : state.flows) {
        const FlowKey& key = item.first;
        const FlowStats& flow = item.second;
        const double flow_duration = std::max(0.001, flow.last_seen - flow.first_seen);
        const double same_host_rate = state.flows.empty()
                                          ? 0
                                          : static_cast<double>(state.host_counts.at(key.dst_ip)) /
                                                static_cast<double>(state.flows.size());

        if (!first) {
            std::cout << ",";
        }
        first = false;
        std::cout << "{"
                  << "\"source_ip\":\"" << json_escape(key.src_ip) << "\","
                  << "\"destination_ip\":\"" << json_escape(key.dst_ip) << "\","
                  << "\"source_bytes\":" << flow.source_bytes << ","
                  << "\"destination_bytes\":" << flow.destination_bytes << ","
                  << "\"packet_count\":" << flow.packet_count << ","
                  << "\"duration\":" << std::fixed << std::setprecision(3) << flow_duration << ","
                  << "\"protocol\":\"" << key.protocol << "\","
                  << "\"service\":\"" << service_name(key.dst_port) << "\","
                  << "\"flag\":\"" << flow.flag << "\","
                  << "\"failed_login_count\":0,"
                  << "\"connection_rate\":" << std::fixed << std::setprecision(3) << connection_rate << ","
                  << "\"same_host_rate\":" << std::fixed << std::setprecision(3) << same_host_rate << ","
                  << "\"error_rate\":" << std::fixed << std::setprecision(3) << error_rate << ","
                  << "\"source\":\"pcap\""
                  << "}";
    }
    std::cout << "],\"packets\":[";
    first = true;
    for (const auto& packet : state.packets) {
        if (!first) {
            std::cout << ",";
        }
        first = false;
        std::cout << "{"
                  << "\"timestamp\":" << std::fixed << std::setprecision(6) << packet.timestamp << ","
                  << "\"source_ip\":\"" << json_escape(packet.src_ip) << "\","
                  << "\"destination_ip\":\"" << json_escape(packet.dst_ip) << "\","
                  << "\"source_port\":" << packet.src_port << ","
                  << "\"destination_port\":" << packet.dst_port << ","
                  << "\"protocol\":\"" << packet.protocol << "\","
                  << "\"service\":\"" << packet.service << "\","
                  << "\"length\":" << packet.length << ","
                  << "\"flag\":\"" << packet.flag << "\""
                  << "}";
    }
    std::cout << "],\"error\":null}" << std::endl;
}

}  // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    WSADATA winsock_data;
    WSAStartup(MAKEWORD(2, 2), &winsock_data);
#endif
    int duration_seconds = 2;
    std::string device;
    bool stream = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--duration" && i + 1 < argc) {
            duration_seconds = std::max(1, std::atoi(argv[++i]));
        } else if (arg == "--device" && i + 1 < argc) {
            device = argv[++i];
        } else if (arg == "--stream") {
            stream = true;
        }
    }

    if (device.empty()) {
        device = choose_device();
    }
    if (device.empty()) {
        std::cerr << "No capture device found" << std::endl;
        return 2;
    }

    char error_buffer[PCAP_ERRBUF_SIZE] = {};
    pcap_t* handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 500, error_buffer);
    if (handle == nullptr) {
        std::cerr << "Unable to open capture device " << device << ": " << error_buffer << std::endl;
        return 3;
    }

    bpf_program filter {};
    if (pcap_compile(handle, &filter, "ip and (tcp or udp)", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &filter);
        pcap_freecode(&filter);
    }

    std::signal(SIGINT, signal_handler);

    do {
        CaptureState state;
        const auto started = std::chrono::steady_clock::now();

        while (!stop_capture) {
            pcap_dispatch(handle, 64, packet_handler, reinterpret_cast<u_char*>(&state));
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - started);
            if (elapsed.count() >= duration_seconds * 1000) {
                break;
            }
        }
        print_json(state, device, duration_seconds);
    } while (stream && !stop_capture);

    pcap_close(handle);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
