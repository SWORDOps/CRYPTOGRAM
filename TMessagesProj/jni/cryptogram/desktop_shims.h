#pragma once

#include "qt_shims.h"
#include <memory>
#include <cstdint>
#include <unordered_map>

// Base types
using uint32 = uint32_t;
using uint64 = uint64_t;
using int32 = int32_t;
using int64 = int64_t;
using uchar = unsigned char;

namespace gsl {
    template<typename T> using not_null = T;
}
using gsl::not_null;

// Base namespace
namespace base {
    template<typename T> class RandomValueHelper {
    public:
        operator T() { return static_cast<T>(rand()); }
    };
    template<typename T> inline T RandomValue() { return static_cast<T>(rand()); }
    
    inline long long unixtime() { return time(nullptr); }
    
    namespace unixtime {
        inline long long now() { return time(nullptr); }
    }

    template<typename K, typename V> using flat_map = std::map<K, V>;
    template<typename T> using flat_set = std::set<T>;

    inline QString& GlobalStoragePath() {
        static QString path = "/sdcard/cryptogram";
        return path;
    }

    inline void SetGlobalStoragePath(const QString& path) {
        GlobalStoragePath() = path;
    }
}

// Data namespace
namespace Data {
    struct UserId {
        uint64 value;
        explicit UserId(uint64 v) : value(v) {}
    };
    struct PeerId {
        uint64 value;
        explicit PeerId(uint64 v) : value(v) {}
    };
    using MsgId = int32;
    using TimeId = int32;

    class Session {
    public:
        struct Local {
            QString basePath() { return base::GlobalStoragePath(); }
        };
        Local local() { return Local(); }
        UserId userId() { return UserId(0); }
    };

    class PeerData {
    public:
        PeerId id;
        explicit PeerData(PeerId peerId) : id(peerId) {}

        static PeerData* from(Session* s, PeerId peerId) {
            (void)s;
            static std::unordered_map<uint64, std::unique_ptr<PeerData>> peers;
            auto &entry = peers[peerId.value];
            if (!entry) {
                entry = std::make_unique<PeerData>(peerId);
            }
            return entry.get();
        }
    };

    struct EntityType {};
    struct EntityInText {
        EntityInText(EntityType t, int o, int l, QString d) {}
        int offset() const { return 0; }
        int length() const { return 0; }
        QString data() const { return ""; }
        EntityType type() const { return {}; }
        void shiftRight(int n) {}
    };
    
    struct TextWithEntities {
        QString text;
        std::vector<EntityInText> entities;
    };

    class HistoryItem {
    public:
        MsgId id;
        int32 date() const { return 0; }
        TextWithEntities originalText() const { return {}; }
    };
}

using namespace Data;

// Core namespace
namespace Core {
    class App {
    public:
        static App& instance() { static App a; return a; }
        uint64 deviceId() { return 12345; }
    };
}
inline Core::App& App() { return Core::App::instance(); }

// Storage namespace
namespace storage {
}

// History namespace
namespace history {
}

// Main namespace
namespace main {
}
