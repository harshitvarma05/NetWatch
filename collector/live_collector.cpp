#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
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
#include <vector>

namespace {

constexpr int kEthernetHeaderLength = 14;
volatile std::sig_atomic_t stop_capture = 0;

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

struct CaptureState {
    std::map<FlowKey, FlowStats> flows;
    std::map<std::string, uint32_t> host_counts;
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
    if ((flags & TH_SYN) && !(flags & TH_ACK)) {
        return "S0";
    }
    if (flags & TH_RST) {
        return "RSTO";
    }
    if (flags & TH_FIN) {
        return "SF";
    }
    if (flags & TH_ACK) {
        return "SF";
    }
    return "REJ";
}

void signal_handler(int) {
    stop_capture = 1;
}

void packet_handler(u_char* user, const pcap_pkthdr* header, const u_char* packet) {
    auto* state = reinterpret_cast<CaptureState*>(user);
    if (!header || !packet || header->caplen < kEthernetHeaderLength + sizeof(ip)) {
        return;
    }

    const auto* ip_header = reinterpret_cast<const ip*>(packet + kEthernetHeaderLength);
    if (ip_header->ip_v != 4) {
        return;
    }

    const int ip_header_length = ip_header->ip_hl * 4;
    if (ip_header_length < 20 ||
        header->caplen < static_cast<bpf_u_int32>(kEthernetHeaderLength + ip_header_length)) {
        return;
    }

    char source_buffer[INET_ADDRSTRLEN] = {};
    char destination_buffer[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &ip_header->ip_src, source_buffer, sizeof(source_buffer));
    inet_ntop(AF_INET, &ip_header->ip_dst, destination_buffer, sizeof(destination_buffer));

    FlowKey key;
    key.src_ip = source_buffer;
    key.dst_ip = destination_buffer;
    key.protocol = ip_header->ip_p == IPPROTO_TCP ? "tcp" : ip_header->ip_p == IPPROTO_UDP ? "udp" : "";
    if (key.protocol.empty()) {
        return;
    }

    const u_char* transport = packet + kEthernetHeaderLength + ip_header_length;
    const int remaining = header->caplen - kEthernetHeaderLength - ip_header_length;
    std::string flag = "SF";

    if (ip_header->ip_p == IPPROTO_TCP) {
        if (remaining < static_cast<int>(sizeof(tcphdr))) {
            return;
        }
        const auto* tcp = reinterpret_cast<const tcphdr*>(transport);
        key.src_port = ntohs(tcp->th_sport);
        key.dst_port = ntohs(tcp->th_dport);
        flag = tcp_flag(tcp->th_flags);
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        if (remaining < static_cast<int>(sizeof(udphdr))) {
            return;
        }
        const auto* udp = reinterpret_cast<const udphdr*>(transport);
        key.src_port = ntohs(udp->uh_sport);
        key.dst_port = ntohs(udp->uh_dport);
    }

    const double seen_at = timestamp_seconds(header->ts);
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
    std::cout << "],\"error\":null}" << std::endl;
}

}  // namespace

int main(int argc, char** argv) {
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
    return 0;
}
