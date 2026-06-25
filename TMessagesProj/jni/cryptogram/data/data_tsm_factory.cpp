#pragma once
#include "data_tsm_interface.h"

namespace Data {
class SignalTSMFactory {
public:
    static std::unique_ptr<SignalTSMIntegration> Create(Session* session) {
        return std::make_unique<SignalTSMIntegration>(session);
    }
};
}
